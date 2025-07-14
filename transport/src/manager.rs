//! Transport manager for handling multiple transport types

use crate::{TransportError, TransportResult};
use zMesh_core::{
    transport::{
        Transport, Connection, Listener, TransportType, TransportConfig,
        ConnectionId, ConnectionStats,
    },
    zMeshResult, PeerId,
};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    time::interval,
};

/// Transport manager that handles multiple transport types
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<TransportType, Arc<dyn Transport>>>>,
    listeners: Arc<RwLock<HashMap<String, Arc<dyn Listener>>>>,
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<dyn Connection>>>>,
    config: TransportConfig,
    stats: Arc<RwLock<TransportManagerStats>>,
    shutdown_sender: Option<mpsc::UnboundedSender<()>>,
}

impl TransportManager {
    /// Create new transport manager
    pub async fn new(config: TransportConfig) -> TransportResult<Self> {
        let mut manager = Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            stats: Arc::new(RwLock::new(TransportManagerStats::default())),
            shutdown_sender: None,
        };
        
        // Initialize enabled transports
        manager.initialize_transports().await?;
        
        // Start background tasks
        manager.start_background_tasks();
        
        Ok(manager)
    }
    
    /// Initialize all enabled transports
    async fn initialize_transports(&mut self) -> TransportResult<()> {
        let mut transports = self.transports.write();
        
        for transport_type in &self.config.enabled_transports {
            match crate::create_transport(*transport_type, &self.config).await {
                Ok(transport) => {
                    transports.insert(*transport_type, transport);
                    tracing::info!("Initialized {:?} transport", transport_type);
                }
                Err(e) => {
                    tracing::error!("Failed to initialize {:?} transport: {}", transport_type, e);
                    if self.config.require_all_transports {
                        return Err(TransportError::Config(
                            format!("Required transport {:?} failed to initialize", transport_type)
                        ));
                    }
                }
            }
        }
        
        if transports.is_empty() {
            return Err(TransportError::Config(
                "No transports could be initialized".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Start background tasks
    fn start_background_tasks(&mut self) {
        let (shutdown_sender, mut shutdown_receiver) = mpsc::unbounded_channel();
        self.shutdown_sender = Some(shutdown_sender);
        
        // Connection cleanup task
        let connections = self.connections.clone();
        let stats = self.stats.clone();
        let cleanup_interval = self.config.connection_cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::cleanup_stale_connections(&connections, &stats).await;
                    }
                    _ = shutdown_receiver.recv() => {
                        break;
                    }
                }
            }
        });
        
        // Stats collection task
        let connections_clone = self.connections.clone();
        let stats_clone = self.stats.clone();
        let stats_interval = Duration::from_secs(60);
        
        tokio::spawn(async move {
            let mut interval = interval(stats_interval);
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::update_stats(&connections_clone, &stats_clone).await;
                    }
                    _ = shutdown_receiver.recv() => {
                        break;
                    }
                }
            }
        });
    }
    
    /// Connect using the best available transport
    pub async fn connect(&self, address: &str) -> zMeshResult<Arc<dyn Connection>> {
        let transport_type = self.detect_transport_type(address)?;
        self.connect_with_transport(transport_type, address).await
    }
    
    /// Connect using a specific transport
    pub async fn connect_with_transport(
        &self,
        transport_type: TransportType,
        address: &str,
    ) -> zMeshResult<Arc<dyn Connection>> {
        let transport = {
            let transports = self.transports.read();
            transports.get(&transport_type)
                .ok_or_else(|| TransportError::NotSupported(
                    format!("Transport {:?} not available", transport_type)
                ))?
                .clone()
        };
        
        let connection = transport.connect(address).await?;
        let connection_id = connection.connection_id();
        
        // Store connection
        self.connections.write().insert(connection_id, connection.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_connections += 1;
            stats.active_connections += 1;
            stats.connections_by_transport
                .entry(transport_type)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }
        
        tracing::info!("Connected to {} using {:?} transport", address, transport_type);
        
        Ok(connection)
    }
    
    /// Start listening on all enabled transports
    pub async fn listen_all(&self, base_address: &str) -> zMeshResult<Vec<Arc<dyn Listener>>> {
        let mut listeners = Vec::new();
        let transports = self.transports.read().clone();
        
        for (transport_type, transport) in transports {
            let address = self.format_address_for_transport(base_address, transport_type)?;
            
            match transport.listen(&address).await {
                Ok(listener) => {
                    let listener_key = format!("{}:{}", transport_type as u8, address);
                    self.listeners.write().insert(listener_key, listener.clone());
                    listeners.push(listener);
                    
                    tracing::info!("Listening on {} with {:?} transport", address, transport_type);
                }
                Err(e) => {
                    tracing::error!("Failed to listen on {} with {:?}: {}", address, transport_type, e);
                    if self.config.require_all_transports {
                        return Err(e);
                    }
                }
            }
        }
        
        if listeners.is_empty() {
            return Err(TransportError::Config(
                "No listeners could be started".to_string()
            ).into());
        }
        
        Ok(listeners)
    }
    
    /// Listen on a specific transport
    pub async fn listen_with_transport(
        &self,
        transport_type: TransportType,
        address: &str,
    ) -> zMeshResult<Arc<dyn Listener>> {
        let transport = {
            let transports = self.transports.read();
            transports.get(&transport_type)
                .ok_or_else(|| TransportError::NotSupported(
                    format!("Transport {:?} not available", transport_type)
                ))?
                .clone()
        };
        
        let listener = transport.listen(address).await?;
        let listener_key = format!("{}:{}", transport_type as u8, address);
        self.listeners.write().insert(listener_key, listener.clone());
        
        tracing::info!("Listening on {} with {:?} transport", address, transport_type);
        
        Ok(listener)
    }
    
    /// Close a specific connection
    pub async fn close_connection(&self, connection_id: ConnectionId) -> zMeshResult<()> {
        if let Some(connection) = self.connections.write().remove(&connection_id) {
            let transport_type = connection.transport_type();
            
            // Close the connection
            connection.close().await?;
            
            // Update stats
            {
                let mut stats = self.stats.write();
                stats.active_connections = stats.active_connections.saturating_sub(1);
                if let Some(count) = stats.connections_by_transport.get_mut(&transport_type) {
                    *count = count.saturating_sub(1);
                }
            }
            
            tracing::debug!("Closed connection {}", connection_id.0);
        }
        
        Ok(())
    }
    
    /// Get connection by ID
    pub fn get_connection(&self, connection_id: ConnectionId) -> Option<Arc<dyn Connection>> {
        self.connections.read().get(&connection_id).cloned()
    }
    
    /// List all active connections
    pub fn list_connections(&self) -> Vec<ConnectionId> {
        self.connections.read().keys().cloned().collect()
    }
    
    /// Get connections by transport type
    pub fn get_connections_by_transport(&self, transport_type: TransportType) -> Vec<Arc<dyn Connection>> {
        self.connections.read()
            .values()
            .filter(|conn| conn.transport_type() == transport_type)
            .cloned()
            .collect()
    }
    
    /// Get connections by peer ID
    pub fn get_connections_by_peer(&self, peer_id: &PeerId) -> Vec<Arc<dyn Connection>> {
        self.connections.read()
            .values()
            .filter(|conn| conn.peer_id().as_ref() == Some(peer_id))
            .cloned()
            .collect()
    }
    
    /// Get available transport types
    pub fn available_transports(&self) -> Vec<TransportType> {
        self.transports.read().keys().cloned().collect()
    }
    
    /// Get transport manager statistics
    pub fn stats(&self) -> TransportManagerStats {
        self.stats.read().clone()
    }
    
    /// Shutdown the transport manager
    pub async fn shutdown(&mut self) -> zMeshResult<()> {
        // Signal background tasks to stop
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        
        // Close all connections
        let connections: Vec<_> = self.connections.read().values().cloned().collect();
        for connection in connections {
            let _ = connection.close().await;
        }
        self.connections.write().clear();
        
        // Close all listeners
        let listeners: Vec<_> = self.listeners.read().values().cloned().collect();
        for listener in listeners {
            let _ = listener.close().await;
        }
        self.listeners.write().clear();
        
        // Shutdown all transports
        let transports: Vec<_> = self.transports.read().values().cloned().collect();
        for transport in transports {
            let _ = transport.shutdown().await;
        }
        self.transports.write().clear();
        
        tracing::info!("Transport manager shutdown complete");
        Ok(())
    }
    
    /// Detect transport type from address
    fn detect_transport_type(&self, address: &str) -> TransportResult<TransportType> {
        if address.starts_with("ws://") || address.starts_with("wss://") {
            Ok(TransportType::WebSocket)
        } else if address.starts_with("webrtc://") {
            Ok(TransportType::WebRtc)
        } else {
            // Default to WebSocket for plain addresses
            Ok(TransportType::WebSocket)
        }
    }
    
    /// Format address for specific transport
    fn format_address_for_transport(
        &self,
        base_address: &str,
        transport_type: TransportType,
    ) -> TransportResult<String> {
        match transport_type {
            TransportType::WebSocket => {
                if base_address.starts_with("ws://") || base_address.starts_with("wss://") {
                    Ok(base_address.to_string())
                } else {
                    Ok(base_address.to_string()) // Plain address for listener
                }
            }
            TransportType::WebRtc => {
                if base_address.starts_with("webrtc://") {
                    Ok(base_address.to_string())
                } else {
                    Ok(format!("webrtc://{}", base_address))
                }
            }
        }
    }
    
    /// Cleanup stale connections
    async fn cleanup_stale_connections(
        connections: &Arc<RwLock<HashMap<ConnectionId, Arc<dyn Connection>>>>,
        stats: &Arc<RwLock<TransportManagerStats>>,
    ) {
        let stale_threshold = Duration::from_secs(300); // 5 minutes
        let mut stale_connections = Vec::new();
        
        // Find stale connections
        {
            let connections_guard = connections.read();
            for (id, connection) in connections_guard.iter() {
                let conn_stats = connection.stats();
                if conn_stats.last_activity.elapsed() > stale_threshold {
                    stale_connections.push(*id);
                }
            }
        }
        
        // Remove stale connections
        if !stale_connections.is_empty() {
            let mut connections_guard = connections.write();
            let mut stats_guard = stats.write();
            
            for connection_id in stale_connections {
                if let Some(connection) = connections_guard.remove(&connection_id) {
                    let _ = connection.close().await;
                    stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
                    
                    tracing::debug!("Cleaned up stale connection {}", connection_id.0);
                }
            }
        }
    }
    
    /// Update statistics
    async fn update_stats(
        connections: &Arc<RwLock<HashMap<ConnectionId, Arc<dyn Connection>>>>,
        stats: &Arc<RwLock<TransportManagerStats>>,
    ) {
        let connections_guard = connections.read();
        let mut stats_guard = stats.write();
        
        // Update connection counts
        stats_guard.active_connections = connections_guard.len();
        
        // Update transport-specific counts
        stats_guard.connections_by_transport.clear();
        for connection in connections_guard.values() {
            let transport_type = connection.transport_type();
            *stats_guard.connections_by_transport
                .entry(transport_type)
                .or_insert(0) += 1;
        }
        
        // Calculate total bytes transferred
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        
        for connection in connections_guard.values() {
            let conn_stats = connection.stats();
            total_bytes_sent += conn_stats.bytes_sent;
            total_bytes_received += conn_stats.bytes_received;
        }
        
        stats_guard.total_bytes_sent = total_bytes_sent;
        stats_guard.total_bytes_received = total_bytes_received;
        stats_guard.last_updated = Instant::now();
    }
}

/// Transport manager statistics
#[derive(Debug, Clone, Default)]
pub struct TransportManagerStats {
    /// Total connections ever created
    pub total_connections: usize,
    /// Currently active connections
    pub active_connections: usize,
    /// Connections by transport type
    pub connections_by_transport: HashMap<TransportType, usize>,
    /// Total bytes sent across all connections
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections
    pub total_bytes_received: u64,
    /// Last statistics update time
    pub last_updated: Instant,
}

impl TransportManagerStats {
    /// Get total data transferred
    pub fn total_data_transferred(&self) -> u64 {
        self.total_bytes_sent + self.total_bytes_received
    }
    
    /// Get connection count for transport type
    pub fn connections_for_transport(&self, transport_type: TransportType) -> usize {
        self.connections_by_transport.get(&transport_type).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::transport::TransportConfig;
    
    #[tokio::test]
    async fn test_transport_manager_creation() {
        let config = TransportConfig::default();
        let manager = TransportManager::new(config).await;
        assert!(manager.is_ok());
    }
    
    #[test]
    fn test_transport_type_detection() {
        let config = TransportConfig::default();
        let manager = TransportManager {
            transports: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(TransportManagerStats::default())),
            shutdown_sender: None,
        };
        
        assert_eq!(
            manager.detect_transport_type("ws://example.com").unwrap(),
            TransportType::WebSocket
        );
        
        assert_eq!(
            manager.detect_transport_type("webrtc://example.com").unwrap(),
            TransportType::WebRtc
        );
        
        assert_eq!(
            manager.detect_transport_type("127.0.0.1:8080").unwrap(),
            TransportType::WebSocket
        );
    }
}