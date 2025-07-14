//! Transport layer implementations for zMesh
//! 
//! This module provides WebRTC and WebSocket transport implementations
//! that integrate with the zMesh core transport traits.

pub mod webrtc;
pub mod websocket;
pub mod manager;
pub mod error;
pub mod utils;

use zMesh_core::{
    transport::{Transport, Connection, Listener, TransportType, TransportConfig},
    zMeshResult,
};
use std::sync::Arc;

pub use error::TransportError;
pub use manager::TransportManager;
pub use webrtc::WebRtcTransport;
pub use websocket::WebSocketTransport;

/// Create a new transport based on type
pub async fn create_transport(
    transport_type: TransportType,
    config: &TransportConfig,
) -> zMeshResult<Arc<dyn Transport>> {
    match transport_type {
        TransportType::WebRtc => {
            let transport = WebRtcTransport::new(config.webrtc.clone()).await?;
            Ok(Arc::new(transport))
        }
        TransportType::WebSocket => {
            let transport = WebSocketTransport::new(config.websocket.clone()).await?;
            Ok(Arc::new(transport))
        }
    }
}

/// Transport factory for creating transports
pub struct TransportFactory;

impl TransportFactory {
    /// Create all available transports
    pub async fn create_all(config: &TransportConfig) -> zMeshResult<Vec<Arc<dyn Transport>>> {
        let mut transports = Vec::new();
        
        // Create WebRTC transport
        if config.enabled_transports.contains(&TransportType::WebRtc) {
            match WebRtcTransport::new(config.webrtc.clone()).await {
                Ok(transport) => transports.push(Arc::new(transport) as Arc<dyn Transport>),
                Err(e) => tracing::warn!("Failed to create WebRTC transport: {}", e),
            }
        }
        
        // Create WebSocket transport
        if config.enabled_transports.contains(&TransportType::WebSocket) {
            match WebSocketTransport::new(config.websocket.clone()).await {
                Ok(transport) => transports.push(Arc::new(transport) as Arc<dyn Transport>),
                Err(e) => tracing::warn!("Failed to create WebSocket transport: {}", e),
            }
        }
        
        if transports.is_empty() {
            return Err(zMesh_core::zMeshError::Transport(
                zMesh_core::transport::TransportError::NoTransportsAvailable
            ));
        }
        
        Ok(transports)
    }
    
    /// Create transport by type
    pub async fn create_by_type(
        transport_type: TransportType,
        config: &TransportConfig,
    ) -> zMeshResult<Arc<dyn Transport>> {
        create_transport(transport_type, config).await
    }
}

/// Re-export commonly used types
pub use zMesh_core::transport::{
    ConnectionId, ConnectionStats, TransportMessage,
    WebRtcConfig, WebSocketConfig, TurnServer,
};

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::transport::TransportConfig;
    
    #[tokio::test]
    async fn test_transport_factory() {
        let config = TransportConfig::default();
        
        // Test creating all transports
        let transports = TransportFactory::create_all(&config).await;
        assert!(transports.is_ok());
        
        let transports = transports.unwrap();
        assert!(!transports.is_empty());
    }
    
    #[tokio::test]
    async fn test_create_websocket_transport() {
        let config = TransportConfig::default();
        
        let transport = TransportFactory::create_by_type(
            TransportType::WebSocket,
            &config
        ).await;
        
        assert!(transport.is_ok());
    }
}