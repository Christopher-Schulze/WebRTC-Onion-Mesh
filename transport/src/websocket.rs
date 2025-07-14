//! WebSocket transport implementation

use crate::{TransportError, TransportResult};
use zMesh_core::{
    transport::{
        Transport, Connection, Listener, TransportType, TransportMessage,
        ConnectionId, ConnectionStats, WebSocketConfig,
    },
    zMeshResult, PeerId,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message, WebSocketStream,
};
use url::Url;

/// WebSocket transport implementation
pub struct WebSocketTransport {
    config: WebSocketConfig,
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebSocketConnection>>>>,
    listeners: Arc<RwLock<HashMap<SocketAddr, Arc<WebSocketListener>>>>,
    connection_counter: AtomicU64,
}

impl WebSocketTransport {
    /// Create new WebSocket transport
    pub async fn new(config: WebSocketConfig) -> TransportResult<Self> {
        Ok(Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(HashMap::new())),
            connection_counter: AtomicU64::new(0),
        })
    }
    
    /// Generate new connection ID
    fn next_connection_id(&self) -> ConnectionId {
        ConnectionId::new(self.connection_counter.fetch_add(1, Ordering::SeqCst))
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }
    
    async fn connect(&self, address: &str) -> zMeshResult<Arc<dyn Connection>> {
        let url = Url::parse(address)
            .map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
        
        // Connect with timeout
        let connect_future = connect_async(&url);
        let (ws_stream, _) = timeout(self.config.connect_timeout, connect_future)
            .await
            .map_err(|_| TransportError::Timeout("Connection timeout".to_string()))?
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        
        let connection_id = self.next_connection_id();
        let connection = Arc::new(WebSocketConnection::new(
            connection_id,
            ws_stream,
            address.to_string(),
            false, // outbound
        ));
        
        // Store connection
        self.connections.write().insert(connection_id, connection.clone());
        
        tracing::info!("WebSocket connection established to {}", address);
        
        Ok(connection as Arc<dyn Connection>)
    }
    
    async fn listen(&self, address: &str) -> zMeshResult<Arc<dyn Listener>> {
        let socket_addr: SocketAddr = address.parse()
            .map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
        
        let tcp_listener = TcpListener::bind(socket_addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        
        let actual_addr = tcp_listener.local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))?;
        
        let listener = Arc::new(WebSocketListener::new(
            tcp_listener,
            actual_addr,
            self.connections.clone(),
            self.connection_counter.clone(),
        ));
        
        // Store listener
        self.listeners.write().insert(actual_addr, listener.clone());
        
        tracing::info!("WebSocket listener started on {}", actual_addr);
        
        Ok(listener as Arc<dyn Listener>)
    }
    
    async fn close_connection(&self, connection_id: ConnectionId) -> zMeshResult<()> {
        if let Some(connection) = self.connections.write().remove(&connection_id) {
            connection.close().await?;
            tracing::debug!("Closed WebSocket connection {}", connection_id.0);
        }
        Ok(())
    }
    
    fn get_connection(&self, connection_id: ConnectionId) -> Option<Arc<dyn Connection>> {
        self.connections.read().get(&connection_id)
            .map(|conn| conn.clone() as Arc<dyn Connection>)
    }
    
    fn list_connections(&self) -> Vec<ConnectionId> {
        self.connections.read().keys().cloned().collect()
    }
    
    async fn shutdown(&self) -> zMeshResult<()> {
        // Close all connections
        let connections: Vec<_> = self.connections.read().values().cloned().collect();
        for connection in connections {
            let _ = connection.close().await;
        }
        self.connections.write().clear();
        
        // Close all listeners
        self.listeners.write().clear();
        
        tracing::info!("WebSocket transport shutdown complete");
        Ok(())
    }
}

/// WebSocket connection implementation
pub struct WebSocketConnection {
    id: ConnectionId,
    remote_addr: String,
    is_inbound: bool,
    sender: mpsc::UnboundedSender<Message>,
    receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<Bytes>>>>,
    stats: Arc<RwLock<ConnectionStats>>,
    close_sender: Option<oneshot::Sender<()>>,
}

impl WebSocketConnection {
    /// Create new WebSocket connection
    pub fn new<S>(
        id: ConnectionId,
        ws_stream: WebSocketStream<S>,
        remote_addr: String,
        is_inbound: bool,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (ws_sender, ws_receiver) = ws_stream.split();
        let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
        let (data_sender, data_receiver) = mpsc::unbounded_channel();
        let (close_sender, close_receiver) = oneshot::channel();
        
        let stats = Arc::new(RwLock::new(ConnectionStats {
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        }));
        
        // Spawn sender task
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            let mut ws_sender = ws_sender;
            let mut msg_receiver = msg_receiver;
            let mut close_receiver = close_receiver;
            
            loop {
                tokio::select! {
                    msg = msg_receiver.recv() => {
                        match msg {
                            Some(message) => {
                                if let Err(e) = ws_sender.send(message).await {
                                    tracing::error!("Failed to send WebSocket message: {}", e);
                                    break;
                                }
                                
                                // Update stats
                                let mut stats = stats_clone.write();
                                stats.messages_sent += 1;
                                stats.last_activity = Instant::now();
                            }
                            None => break,
                        }
                    }
                    _ = &mut close_receiver => {
                        let _ = ws_sender.close().await;
                        break;
                    }
                }
            }
        });
        
        // Spawn receiver task
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            let mut ws_receiver = ws_receiver;
            let data_sender = data_sender;
            
            while let Some(msg) = ws_receiver.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        // Update stats
                        {
                            let mut stats = stats_clone.write();
                            stats.bytes_received += data.len() as u64;
                            stats.messages_received += 1;
                            stats.last_activity = Instant::now();
                        }
                        
                        if data_sender.send(Bytes::from(data)).is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => {
                        tracing::debug!("WebSocket connection closed by peer");
                        break;
                    }
                    Ok(Message::Ping(data)) => {
                        // Respond with pong
                        let pong = Message::Pong(data);
                        if msg_sender.send(pong).is_err() {
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        // Update activity timestamp
                        stats_clone.write().last_activity = Instant::now();
                    }
                    Ok(Message::Text(_)) => {
                        // Ignore text messages in binary protocol
                        tracing::warn!("Received unexpected text message on binary WebSocket");
                    }
                    Err(e) => {
                        tracing::error!("WebSocket receive error: {}", e);
                        break;
                    }
                }
            }
        });
        
        Self {
            id,
            remote_addr,
            is_inbound,
            sender: msg_sender,
            receiver: Arc::new(RwLock::new(Some(data_receiver))),
            stats,
            close_sender: Some(close_sender),
        }
    }
}

#[async_trait]
impl Connection for WebSocketConnection {
    fn connection_id(&self) -> ConnectionId {
        self.id
    }
    
    fn remote_address(&self) -> String {
        self.remote_addr.clone()
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }
    
    fn is_inbound(&self) -> bool {
        self.is_inbound
    }
    
    async fn send(&self, message: TransportMessage) -> zMeshResult<()> {
        let data = bincode::serialize(&message)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        
        let ws_message = Message::Binary(data.clone());
        
        self.sender.send(ws_message)
            .map_err(|_| TransportError::ConnectionClosed("Connection closed".to_string()))?;
        
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.bytes_sent += data.len() as u64;
            stats.messages_sent += 1;
            stats.last_activity = Instant::now();
        }
        
        Ok(())
    }
    
    async fn receive(&self) -> zMeshResult<TransportMessage> {
        let mut receiver_guard = self.receiver.write();
        let receiver = receiver_guard.as_mut()
            .ok_or_else(|| TransportError::ConnectionClosed("Connection closed".to_string()))?;
        
        let data = receiver.recv().await
            .ok_or_else(|| TransportError::ConnectionClosed("Connection closed".to_string()))?;
        
        let message = bincode::deserialize(&data)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        
        Ok(message)
    }
    
    async fn close(&self) -> zMeshResult<()> {
        // Signal close to sender task
        if let Some(close_sender) = &self.close_sender {
            let _ = close_sender.send(());
        }
        
        // Close receiver
        self.receiver.write().take();
        
        tracing::debug!("WebSocket connection {} closed", self.id.0);
        Ok(())
    }
    
    fn stats(&self) -> ConnectionStats {
        self.stats.read().clone()
    }
    
    fn peer_id(&self) -> Option<PeerId> {
        // TODO: Extract peer ID from handshake or certificate
        None
    }
}

/// WebSocket listener implementation
pub struct WebSocketListener {
    tcp_listener: Arc<RwLock<Option<TcpListener>>>,
    local_addr: SocketAddr,
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebSocketConnection>>>>,
    connection_counter: Arc<AtomicU64>,
    accept_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<Arc<dyn Connection>>>>>,
}

impl WebSocketListener {
    /// Create new WebSocket listener
    pub fn new(
        tcp_listener: TcpListener,
        local_addr: SocketAddr,
        connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebSocketConnection>>>>,
        connection_counter: Arc<AtomicU64>,
    ) -> Self {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel();
        
        let tcp_listener = Arc::new(RwLock::new(Some(tcp_listener)));
        let tcp_listener_clone = tcp_listener.clone();
        let connections_clone = connections.clone();
        let connection_counter_clone = connection_counter.clone();
        
        // Spawn accept task
        tokio::spawn(async move {
            let mut listener_guard = tcp_listener_clone.write();
            if let Some(listener) = listener_guard.take() {
                drop(listener_guard); // Release the lock
                
                loop {
                    match listener.accept().await {
                        Ok((stream, peer_addr)) => {
                            tracing::debug!("Accepted TCP connection from {}", peer_addr);
                            
                            // Perform WebSocket handshake
                            match accept_async(stream).await {
                                Ok(ws_stream) => {
                                    let connection_id = ConnectionId::new(
                                        connection_counter_clone.fetch_add(1, Ordering::SeqCst)
                                    );
                                    
                                    let connection = Arc::new(WebSocketConnection::new(
                                        connection_id,
                                        ws_stream,
                                        peer_addr.to_string(),
                                        true, // inbound
                                    ));
                                    
                                    // Store connection
                                    connections_clone.write().insert(connection_id, connection.clone());
                                    
                                    // Send to accept channel
                                    if accept_sender.send(connection as Arc<dyn Connection>).is_err() {
                                        break;
                                    }
                                    
                                    tracing::info!("WebSocket connection accepted from {}", peer_addr);
                                }
                                Err(e) => {
                                    tracing::error!("WebSocket handshake failed with {}: {}", peer_addr, e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to accept TCP connection: {}", e);
                            break;
                        }
                    }
                }
            }
        });
        
        Self {
            tcp_listener,
            local_addr,
            connections,
            connection_counter,
            accept_receiver: Arc::new(RwLock::new(Some(accept_receiver))),
        }
    }
}

#[async_trait]
impl Listener for WebSocketListener {
    fn local_address(&self) -> String {
        format!("ws://{}", self.local_addr)
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }
    
    async fn accept(&self) -> zMeshResult<Arc<dyn Connection>> {
        let mut receiver_guard = self.accept_receiver.write();
        let receiver = receiver_guard.as_mut()
            .ok_or_else(|| TransportError::ConnectionClosed("Listener closed".to_string()))?;
        
        let connection = receiver.recv().await
            .ok_or_else(|| TransportError::ConnectionClosed("Listener closed".to_string()))?;
        
        Ok(connection)
    }
    
    async fn close(&self) -> zMeshResult<()> {
        // Close the TCP listener
        self.tcp_listener.write().take();
        
        // Close the accept receiver
        self.accept_receiver.write().take();
        
        tracing::info!("WebSocket listener on {} closed", self.local_addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::transport::WebSocketConfig;
    
    #[tokio::test]
    async fn test_websocket_transport_creation() {
        let config = WebSocketConfig::default();
        let transport = WebSocketTransport::new(config).await;
        assert!(transport.is_ok());
    }
    
    #[tokio::test]
    async fn test_websocket_listener() {
        let config = WebSocketConfig::default();
        let transport = WebSocketTransport::new(config).await.unwrap();
        
        let listener = transport.listen("127.0.0.1:0").await;
        assert!(listener.is_ok());
        
        let listener = listener.unwrap();
        assert!(listener.local_address().starts_with("ws://127.0.0.1:"));
    }
}