//! Exit node implementation for onion routing
//! Handles final packet decryption and external connections

use crate::circuit::{CircuitId, CircuitState};
use crate::crypto::{OnionCrypto, OnionEncryptedData, HopKeys};
use crate::error::{OnionResult, ExitError};
use crate::packet::{
    OnionPacket, OnionCommand, OnionPayload, PacketBuilder
};
use crnet_core::peer::PeerId;
use crnet_transport::TransportManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, timeout};
use uuid::Uuid;

/// Exit node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitConfig {
    /// Maximum concurrent exit connections
    pub max_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Maximum data transfer per connection
    pub max_transfer_size: u64,
    /// Allowed destination ports
    pub allowed_ports: Vec<u16>,
    /// Blocked destination IPs/ranges
    pub blocked_ips: Vec<String>,
    /// Blocked domains
    pub blocked_domains: Vec<String>,
    /// Enable traffic filtering
    pub enable_filtering: bool,
    /// Enable bandwidth limiting
    pub enable_bandwidth_limit: bool,
    /// Bandwidth limit in bytes per second
    pub bandwidth_limit: u64,
    /// Enable connection logging
    pub log_connections: bool,
    /// Enable statistics collection
    pub collect_stats: bool,
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout: Duration::from_secs(30),
            max_transfer_size: 100 * 1024 * 1024, // 100 MB
            allowed_ports: vec![80, 443, 993, 995], // HTTP, HTTPS, IMAPS, POP3S
            blocked_ips: vec![
                "127.0.0.0/8".to_string(),    // Localhost
                "10.0.0.0/8".to_string(),     // Private
                "172.16.0.0/12".to_string(),  // Private
                "192.168.0.0/16".to_string(), // Private
            ],
            blocked_domains: vec![
                "localhost".to_string(),
                "*.local".to_string(),
            ],
            enable_filtering: true,
            enable_bandwidth_limit: false,
            bandwidth_limit: 10 * 1024 * 1024, // 10 MB/s
            log_connections: true,
            collect_stats: true,
        }
    }
}

/// Exit connection types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// TCP connection
    Tcp,
    /// UDP connection
    Udp,
    /// HTTP connection
    Http,
    /// HTTPS connection
    Https,
}

/// Exit connection information
#[derive(Debug, Clone)]
struct ExitConnection {
    /// Connection ID
    id: String,
    /// Circuit ID
    circuit_id: CircuitId,
    /// Stream ID within circuit
    stream_id: u16,
    /// Connection type
    connection_type: ConnectionType,
    /// Destination address
    destination: SocketAddr,
    /// Connection creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Connection state
    state: ConnectionState,
}

/// Connection state
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    /// Connecting to destination
    Connecting,
    /// Connected and active
    Connected,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
    /// Connection failed
    Failed(String),
}

impl ExitConnection {
    /// Create a new exit connection
    fn new(
        circuit_id: CircuitId,
        stream_id: u16,
        connection_type: ConnectionType,
        destination: SocketAddr,
    ) -> Self {
        let now = Instant::now();
        
        Self {
            id: Uuid::new_v4().to_string(),
            circuit_id,
            stream_id,
            connection_type,
            destination,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            state: ConnectionState::Connecting,
        }
    }
    
    /// Update activity timestamp
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Check if connection is expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
    
    /// Record sent data
    fn record_sent(&mut self, size: u64) {
        self.bytes_sent += size;
        self.update_activity();
    }
    
    /// Record received data
    fn record_received(&mut self, size: u64) {
        self.bytes_received += size;
        self.update_activity();
    }
    
    /// Get total bytes transferred
    fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

/// Exit node statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExitStats {
    /// Total connections handled
    pub connections_handled: u64,
    /// Active connections
    pub active_connections: usize,
    /// Failed connections
    pub failed_connections: u64,
    /// Blocked connections
    pub blocked_connections: u64,
    /// Total bytes sent to destinations
    pub bytes_sent: u64,
    /// Total bytes received from destinations
    pub bytes_received: u64,
    /// Average connection duration
    pub avg_connection_duration: Duration,
    /// Bandwidth usage
    pub bandwidth_usage: u64,
    /// Last update timestamp
    pub last_update: Instant,
}

/// Traffic filter for exit connections
struct TrafficFilter {
    /// Allowed ports
    allowed_ports: Vec<u16>,
    /// Blocked IP ranges
    blocked_ips: Vec<String>,
    /// Blocked domains
    blocked_domains: Vec<String>,
}

impl TrafficFilter {
    /// Create a new traffic filter
    fn new(
        allowed_ports: Vec<u16>,
        blocked_ips: Vec<String>,
        blocked_domains: Vec<String>,
    ) -> Self {
        Self {
            allowed_ports,
            blocked_ips,
            blocked_domains,
        }
    }
    
    /// Check if connection is allowed
    fn is_allowed(&self, destination: &SocketAddr, domain: Option<&str>) -> bool {
        // Check port
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&destination.port()) {
            return false;
        }
        
        // Check IP
        if self.is_ip_blocked(&destination.ip()) {
            return false;
        }
        
        // Check domain
        if let Some(domain) = domain {
            if self.is_domain_blocked(domain) {
                return false;
            }
        }
        
        true
    }
    
    /// Check if IP is blocked
    fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        for blocked_range in &self.blocked_ips {
            if self.ip_in_range(ip, blocked_range) {
                return true;
            }
        }
        false
    }
    
    /// Check if domain is blocked
    fn is_domain_blocked(&self, domain: &str) -> bool {
        for blocked_domain in &self.blocked_domains {
            if blocked_domain.starts_with('*') {
                let suffix = &blocked_domain[1..];
                if domain.ends_with(suffix) {
                    return true;
                }
            } else if domain == blocked_domain {
                return true;
            }
        }
        false
    }
    
    /// Check if IP is in range (simplified implementation)
    fn ip_in_range(&self, ip: &IpAddr, range: &str) -> bool {
        // Simplified CIDR matching - in production, use a proper CIDR library
        if let Some(slash_pos) = range.find('/') {
            let network = &range[..slash_pos];
            if let Ok(network_ip) = network.parse::<IpAddr>() {
                // Simple prefix matching for demonstration
                match (ip, network_ip) {
                    (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                        let ip_octets = ip4.octets();
                        let net_octets = net4.octets();
                        
                        // Check first octet for /8, first two for /16, etc.
                        let prefix_len: u8 = range[slash_pos + 1..].parse().unwrap_or(32);
                        let octets_to_check = (prefix_len / 8) as usize;
                        
                        for i in 0..octets_to_check.min(4) {
                            if ip_octets[i] != net_octets[i] {
                                return false;
                            }
                        }
                        return true;
                    }
                    _ => false,
                }
            }
        }
        false
    }
}

/// Exit node implementation
pub struct ExitNode {
    /// Exit configuration
    config: ExitConfig,
    /// Active connections
    connections: Arc<RwLock<HashMap<String, ExitConnection>>>,
    /// Cryptographic operations
    crypto: Arc<OnionCrypto>,
    /// Transport manager
    transport: Arc<TransportManager>,
    /// Traffic filter
    traffic_filter: TrafficFilter,
    /// Exit statistics
    stats: Arc<RwLock<ExitStats>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ExitNode {
    /// Create a new exit node
    pub async fn new(
        config: ExitConfig,
        crypto: Arc<OnionCrypto>,
        transport: Arc<TransportManager>,
    ) -> OnionResult<Self> {
        let traffic_filter = TrafficFilter::new(
            config.allowed_ports.clone(),
            config.blocked_ips.clone(),
            config.blocked_domains.clone(),
        );
        
        Ok(Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            crypto,
            transport,
            traffic_filter,
            stats: Arc::new(RwLock::new(ExitStats::default())),
            shutdown_tx: None,
        })
    }
    
    /// Start the exit node
    pub async fn start(&mut self) -> OnionResult<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        // Start background tasks
        self.start_cleanup_task().await;
        self.start_stats_task().await;
        
        // Wait for shutdown signal
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Exit node shutdown requested");
            }
        }
        
        Ok(())
    }
    
    /// Stop the exit node
    pub async fn stop(&mut self) -> OnionResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Close all connections
        let mut connections = self.connections.write().await;
        connections.clear();
        
        Ok(())
    }
    
    /// Handle exit packet
    pub async fn handle_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        match packet.command() {
            OnionCommand::Begin => {
                self.handle_begin_packet(packet).await
            }
            OnionCommand::Data => {
                self.handle_data_packet(packet).await
            }
            OnionCommand::End => {
                self.handle_end_packet(packet).await
            }
            _ => {
                Err(ExitError::UnsupportedCommand(format!("{:?}", packet.command())).into())
            }
        }
    }
    
    /// Handle begin packet (establish connection)
    async fn handle_begin_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        match &packet.payload {
            OnionPayload::BeginRequest { destination, port, flags: _ } => {
                let circuit_id = packet.circuit_id().to_string();
                let stream_id = 1; // TODO: Extract from packet or generate
                
                // Parse destination
                let socket_addr = self.parse_destination(destination, *port).await?;
                
                // Check if connection is allowed
                if self.config.enable_filtering {
                    if !self.traffic_filter.is_allowed(&socket_addr, Some(destination)) {
                        let mut stats = self.stats.write().await;
                        stats.blocked_connections += 1;
                        
                        return Err(ExitError::ConnectionBlocked {
                            destination: socket_addr.to_string(),
                            reason: "Blocked by policy".to_string(),
                        }.into());
                    }
                }
                
                // Check connection limit
                let connections = self.connections.read().await;
                if connections.len() >= self.config.max_connections {
                    return Err(ExitError::TooManyConnections {
                        current: connections.len(),
                        max: self.config.max_connections,
                    }.into());
                }
                drop(connections);
                
                // Create connection
                let connection_type = self.determine_connection_type(*port);
                let mut connection = ExitConnection::new(
                    circuit_id.clone(),
                    stream_id,
                    connection_type.clone(),
                    socket_addr,
                );
                
                // Establish connection based on type
                match connection_type {
                    ConnectionType::Tcp | ConnectionType::Http | ConnectionType::Https => {
                        self.establish_tcp_connection(&mut connection).await?
                    }
                    ConnectionType::Udp => {
                        self.establish_udp_connection(&mut connection).await?
                    }
                }
                
                // Store connection
                let mut connections = self.connections.write().await;
                connections.insert(connection.id.clone(), connection);
                
                // Update statistics
                let mut stats = self.stats.write().await;
                stats.connections_handled += 1;
                stats.active_connections = connections.len();
                
                if self.config.log_connections {
                    println!("Exit connection established: {} -> {}", circuit_id, socket_addr);
                }
                
                Ok(())
            }
            _ => Err(ExitError::InvalidPacketPayload(
                "Expected begin request payload".to_string()
            ).into()),
        }
    }
    
    /// Handle data packet (forward data)
    async fn handle_data_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        match &packet.payload {
            OnionPayload::Data { stream_id, data } => {
                let circuit_id = packet.circuit_id();
                
                // Find connection by circuit and stream ID
                let connection_id = self.find_connection(circuit_id, *stream_id).await
                    .ok_or_else(|| ExitError::ConnectionNotFound {
                        circuit_id: circuit_id.to_string(),
                        stream_id: *stream_id,
                    })?;
                
                // Forward data to destination
                self.forward_data(&connection_id, data).await?;
                
                Ok(())
            }
            _ => Err(ExitError::InvalidPacketPayload(
                "Expected data payload".to_string()
            ).into()),
        }
    }
    
    /// Handle end packet (close connection)
    async fn handle_end_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        match &packet.payload {
            OnionPayload::EndStream { stream_id, reason: _ } => {
                let circuit_id = packet.circuit_id();
                
                // Find and remove connection
                if let Some(connection_id) = self.find_connection(circuit_id, *stream_id).await {
                    self.close_connection(&connection_id).await?;
                }
                
                Ok(())
            }
            _ => Err(ExitError::InvalidPacketPayload(
                "Expected end stream payload".to_string()
            ).into()),
        }
    }
    
    /// Parse destination address
    async fn parse_destination(&self, destination: &str, port: u16) -> OnionResult<SocketAddr> {
        // Try to parse as IP address first
        if let Ok(ip) = destination.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        
        // Try DNS resolution
        match tokio::net::lookup_host((destination, port)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    Ok(addr)
                } else {
                    Err(ExitError::DnsResolutionFailed(destination.to_string()).into())
                }
            }
            Err(e) => Err(ExitError::DnsResolutionFailed(format!("{}: {}", destination, e)).into()),
        }
    }
    
    /// Determine connection type based on port
    fn determine_connection_type(&self, port: u16) -> ConnectionType {
        match port {
            80 => ConnectionType::Http,
            443 => ConnectionType::Https,
            _ => ConnectionType::Tcp, // Default to TCP
        }
    }
    
    /// Establish TCP connection
    async fn establish_tcp_connection(&self, connection: &mut ExitConnection) -> OnionResult<()> {
        let socket_addr = connection.destination;
        
        match timeout(self.config.connection_timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_stream)) => {
                connection.state = ConnectionState::Connected;
                connection.update_activity();
                Ok(())
            }
            Ok(Err(e)) => {
                connection.state = ConnectionState::Failed(e.to_string());
                Err(ExitError::ConnectionFailed {
                    destination: socket_addr.to_string(),
                    error: e.to_string(),
                }.into())
            }
            Err(_) => {
                connection.state = ConnectionState::Failed("Timeout".to_string());
                Err(ExitError::ConnectionTimeout(socket_addr.to_string()).into())
            }
        }
    }
    
    /// Establish UDP connection
    async fn establish_udp_connection(&self, connection: &mut ExitConnection) -> OnionResult<()> {
        // For UDP, we just create a socket and mark as connected
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(_socket) => {
                connection.state = ConnectionState::Connected;
                connection.update_activity();
                Ok(())
            }
            Err(e) => {
                connection.state = ConnectionState::Failed(e.to_string());
                Err(ExitError::ConnectionFailed {
                    destination: connection.destination.to_string(),
                    error: e.to_string(),
                }.into())
            }
        }
    }
    
    /// Forward data to destination
    async fn forward_data(&self, connection_id: &str, data: &[u8]) -> OnionResult<()> {
        // TODO: Implement actual data forwarding
        // This would involve maintaining active TCP/UDP connections
        // and forwarding data bidirectionally
        
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.record_sent(data.len() as u64);
            
            // Update statistics
            drop(connections);
            let mut stats = self.stats.write().await;
            stats.bytes_sent += data.len() as u64;
            
            println!("Forwarding {} bytes to {}", data.len(), connection.destination);
        }
        
        Ok(())
    }
    
    /// Find connection by circuit and stream ID
    async fn find_connection(&self, circuit_id: &str, stream_id: u16) -> Option<String> {
        let connections = self.connections.read().await;
        
        for (id, connection) in connections.iter() {
            if connection.circuit_id == circuit_id && connection.stream_id == stream_id {
                return Some(id.clone());
            }
        }
        
        None
    }
    
    /// Close connection
    async fn close_connection(&self, connection_id: &str) -> OnionResult<()> {
        let mut connections = self.connections.write().await;
        
        if let Some(mut connection) = connections.remove(connection_id) {
            connection.state = ConnectionState::Closed;
            
            // Update statistics
            let mut stats = self.stats.write().await;
            stats.active_connections = connections.len();
            
            if self.config.log_connections {
                println!("Exit connection closed: {} ({})", 
                        connection.destination, connection.total_bytes());
            }
        }
        
        Ok(())
    }
    
    /// Get exit statistics
    pub async fn get_stats(&self) -> ExitStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = ExitStats::default();
    }
    
    /// Get active connections
    pub async fn get_connections(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }
    
    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
    
    /// Start cleanup task for expired connections
    async fn start_cleanup_task(&self) {
        let connections = Arc::clone(&self.connections);
        let stats = Arc::clone(&self.stats);
        let timeout = self.config.connection_timeout;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Remove expired connections
                let mut connections_guard = connections.write().await;
                let initial_count = connections_guard.len();
                
                connections_guard.retain(|_, connection| {
                    !connection.is_expired(timeout) && 
                    connection.state != ConnectionState::Closed
                });
                
                let removed_count = initial_count - connections_guard.len();
                
                if removed_count > 0 {
                    println!("Cleaned up {} expired exit connections", removed_count);
                    
                    // Update statistics
                    let mut stats_guard = stats.write().await;
                    stats_guard.active_connections = connections_guard.len();
                }
            }
        });
    }
    
    /// Start statistics collection task
    async fn start_stats_task(&self) {
        let stats = Arc::clone(&self.stats);
        let connections = Arc::clone(&self.connections);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Update statistics
                let mut stats_guard = stats.write().await;
                let connections_guard = connections.read().await;
                
                stats_guard.active_connections = connections_guard.len();
                stats_guard.last_update = Instant::now();
                
                // Calculate average connection duration
                if !connections_guard.is_empty() {
                    let total_duration: Duration = connections_guard
                        .values()
                        .map(|conn| conn.created_at.elapsed())
                        .sum();
                    
                    stats_guard.avg_connection_duration = 
                        total_duration / connections_guard.len() as u32;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{OnionCipherSuite, OnionKeyExchange};
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_exit_connection_creation() {
        let destination = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            80
        );
        
        let connection = ExitConnection::new(
            "circuit-123".to_string(),
            1,
            ConnectionType::Http,
            destination,
        );
        
        assert_eq!(connection.circuit_id, "circuit-123");
        assert_eq!(connection.stream_id, 1);
        assert_eq!(connection.connection_type, ConnectionType::Http);
        assert_eq!(connection.destination, destination);
        assert_eq!(connection.state, ConnectionState::Connecting);
    }
    
    #[test]
    fn test_traffic_filter() {
        let filter = TrafficFilter::new(
            vec![80, 443],
            vec!["127.0.0.0/8".to_string()],
            vec!["localhost".to_string(), "*.local".to_string()],
        );
        
        // Test allowed port
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80);
        assert!(filter.is_allowed(&addr1, None));
        
        // Test blocked port
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 22);
        assert!(!filter.is_allowed(&addr2, None));
        
        // Test blocked IP
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        assert!(!filter.is_allowed(&addr3, None));
        
        // Test blocked domain
        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80);
        assert!(!filter.is_allowed(&addr4, Some("localhost")));
        assert!(!filter.is_allowed(&addr4, Some("test.local")));
    }
    
    #[tokio::test]
    async fn test_exit_node_creation() {
        let config = ExitConfig::default();
        let crypto = Arc::new(OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
        ));
        let transport = Arc::new(TransportManager::new());
        
        let exit_node = ExitNode::new(config, crypto, transport).await.unwrap();
        
        let stats = exit_node.get_stats().await;
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.connections_handled, 0);
    }
    
    #[test]
    fn test_connection_type_determination() {
        let config = ExitConfig::default();
        let crypto = Arc::new(OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
        ));
        let transport = Arc::new(TransportManager::new());
        
        // This would be in an async context in real usage
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let exit_node = ExitNode::new(config, crypto, transport).await.unwrap();
            
            assert_eq!(exit_node.determine_connection_type(80), ConnectionType::Http);
            assert_eq!(exit_node.determine_connection_type(443), ConnectionType::Https);
            assert_eq!(exit_node.determine_connection_type(22), ConnectionType::Tcp);
        });
    }
    
    #[test]
    fn test_exit_config() {
        let config = ExitConfig::default();
        
        assert_eq!(config.max_connections, 100);
        assert!(config.allowed_ports.contains(&80));
        assert!(config.allowed_ports.contains(&443));
        assert!(config.blocked_ips.contains(&"127.0.0.0/8".to_string()));
        assert!(config.enable_filtering);
        assert!(config.log_connections);
    }
}