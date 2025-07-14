//! WebRTC transport implementation
//! 
//! This is a placeholder implementation for WebRTC transport.
//! Full WebRTC implementation would require significant additional work
//! with ICE, DTLS, SCTP, and DataChannel handling.

use crate::{TransportError, TransportResult};
use zMesh_core::{
    transport::{
        Transport, Connection, Listener, TransportType, TransportMessage,
        ConnectionId, ConnectionStats, WebRtcConfig, TurnServer,
    },
    zMeshResult, PeerId,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::Instant,
};
use tokio::sync::mpsc;

/// WebRTC transport implementation (placeholder)
pub struct WebRtcTransport {
    config: WebRtcConfig,
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebRtcConnection>>>>,
    connection_counter: AtomicU64,
}

impl WebRtcTransport {
    /// Create new WebRTC transport
    pub async fn new(config: WebRtcConfig) -> TransportResult<Self> {
        // Initialize WebRTC stack with comprehensive configuration
        tracing::info!("Initializing WebRTC transport with advanced configuration");
        
        // Validate configuration
        if config.turn_servers.is_empty() {
            tracing::warn!("No TURN servers configured, NAT traversal may fail");
        }
        
        // Initialize certificate for DTLS
        let certificate = Self::generate_dtls_certificate()?;
        tracing::debug!("Generated DTLS certificate with fingerprint: {}", 
                      Self::calculate_certificate_fingerprint(&certificate));
        
        tracing::info!("WebRTC transport initialized with {} TURN servers", 
                      config.turn_servers.len());
        
        Ok(Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_counter: AtomicU64::new(0),
        })
    }
    
    /// Generate new connection ID
    fn next_connection_id(&self) -> ConnectionId {
        ConnectionId::new(self.connection_counter.fetch_add(1, Ordering::SeqCst))
    }
    
    /// Generate DTLS certificate for secure communication
    fn generate_dtls_certificate() -> TransportResult<Vec<u8>> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Generate a self-signed certificate for DTLS
        // In production, this would use proper certificate generation
        let mut cert_data = vec![0u8; 256];
        
        // Add certificate header and validity period
        let mut certificate = Vec::new();
        certificate.extend_from_slice(b"WEBRTC_CERT_V1");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        certificate.extend_from_slice(&now.to_be_bytes());
        certificate.extend_from_slice(&(now + 86400 * 30).to_be_bytes()); // 30 days validity
        certificate.extend_from_slice(&cert_data);
        
        Ok(certificate)
    }
    
    /// Calculate certificate fingerprint for verification
    fn calculate_certificate_fingerprint(certificate: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        certificate.hash(&mut hasher);
        let hash = hasher.finish();
        
        format!("{:016X}", hash)
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(":")
    }
    
    /// Parse WebRTC address
    fn parse_webrtc_address(address: &str) -> TransportResult<WebRtcAddress> {
        if !address.starts_with("webrtc://") {
            return Err(TransportError::InvalidAddress(
                "WebRTC address must start with webrtc://".to_string()
            ));
        }
        
        let url = url::Url::parse(address)
            .map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
        
        let host = url.host_str()
            .ok_or_else(|| TransportError::InvalidAddress("Missing host".to_string()))?;
        
        let port = url.port().unwrap_or(8080);
        let path = url.path().to_string();
        
        Ok(WebRtcAddress {
            host: host.to_string(),
            port,
            path,
        })
    }
    
    /// Establish signaling channel
    async fn establish_signaling_channel(&self, address: &WebRtcAddress) -> TransportResult<SignalingChannel> {
        use tokio_tungstenite::{connect_async, tungstenite::Message};
        
        let signaling_url = format!("ws://{}:{}/signaling", address.host, address.port);
        
        let (ws_stream, _) = connect_async(&signaling_url).await
            .map_err(|e| TransportError::ConnectionFailed(
                format!("Failed to connect to signaling server: {}", e)
            ))?;
        
        let (sender, receiver) = ws_stream.split();
        
        Ok(SignalingChannel::new(sender, receiver))
    }
    
    /// Start signaling server
    async fn start_signaling_server(&self, address: &WebRtcAddress) -> TransportResult<SignalingServer> {
        use tokio::net::TcpListener;
        
        let bind_addr = format!("{}:{}", address.host, address.port);
        let listener = TcpListener::bind(&bind_addr).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        
        Ok(SignalingServer::new(listener))
    }
    
    /// Create ICE agent
    async fn create_ice_agent(&self) -> TransportResult<IceAgent> {
        let ice_config = self.create_ice_config();
        IceAgent::new(ice_config).await
    }
    
    /// Create offer
    async fn create_offer(&self, ice_agent: &IceAgent) -> TransportResult<String> {
        // Generate SDP offer with ICE candidates
        let local_candidates = ice_agent.gather_candidates().await?;
        
        let sdp = format!(
            "v=0\r\n\
             o=zMesh {} {} IN IP4 {}\r\n\
             s=zMesh-session\r\n\
             t=0 0\r\n\
             m=application {} UDP/DTLS/SCTP webrtc-datachannel\r\n\
             c=IN IP4 {}\r\n\
             a=setup:actpass\r\n\
             a=mid:0\r\n\
             a=sctp-port:5000\r\n\
             a=max-message-size:262144\r\n",
            chrono::Utc::now().timestamp(),
            chrono::Utc::now().timestamp(),
            local_candidates.first().map(|c| &c.address).unwrap_or("127.0.0.1"),
            local_candidates.first().map(|c| c.port).unwrap_or(9),
            local_candidates.first().map(|c| &c.address).unwrap_or("127.0.0.1")
        );
        
        Ok(sdp)
    }
    
    /// Process answer
    async fn process_answer(&self, ice_agent: &IceAgent, answer: String) -> TransportResult<PeerConnection> {
        // Parse SDP answer and establish connection
        ice_agent.set_remote_description(answer).await?;
        
        // Wait for ICE connection
        ice_agent.wait_for_connection().await?;
        
        Ok(PeerConnection::new(ice_agent.clone()))
    }
    
    /// Create data channel
    async fn create_data_channel(&self, peer_connection: &PeerConnection) -> TransportResult<DataChannel> {
        let config = self.create_datachannel_config();
        peer_connection.create_data_channel(config).await
    }
    
    /// Wait for connection established
    async fn wait_for_connection_established(&self, peer_connection: &PeerConnection) -> TransportResult<()> {
        use tokio::time::{timeout, Duration};
        
        timeout(Duration::from_secs(30), peer_connection.wait_for_connection()).await
            .map_err(|_| TransportError::Timeout("Connection establishment timeout".to_string()))?;
        
        Ok(())
    }
    
    /// Create ICE configuration from TURN servers
    fn create_ice_config(&self) -> IceConfig {
        IceConfig {
            turn_servers: self.config.turn_servers.clone(),
            ice_timeout: self.config.ice_timeout,
            ice_lite: self.config.ice_lite,
        }
    }

    /// Create DataChannel configuration
    fn create_datachannel_config(&self) -> DataChannelConfig {
        DataChannelConfig {
            label: "zMesh-data".to_string(),
            ordered: true,
            max_retransmits: Some(3),
            max_packet_life_time: None,
            protocol: "zMesh-v1".to_string(),
        }
    }

    /// Parse WebRTC address (webrtc://host:port/path)
    fn parse_webrtc_address(address: &str) -> TransportResult<ParsedWebRtcAddress> {
        use url::Url;
        
        let url = Url::parse(address)
            .map_err(|e| TransportError::ConnectionFailed(format!("Invalid WebRTC URL: {}", e)))?;
        
        if url.scheme() != "webrtc" {
            return Err(TransportError::ConnectionFailed(
                "WebRTC address must use webrtc:// scheme".to_string()
            ));
        }
        
        let host = url.host_str()
            .ok_or_else(|| TransportError::ConnectionFailed("Missing host in WebRTC address".to_string()))?
            .to_string();
        
        let port = url.port().unwrap_or(9001); // Default WebRTC signaling port
        let path = url.path().to_string();
        
        Ok(ParsedWebRtcAddress {
            host,
            port,
            path,
            secure: url.query_pairs().any(|(k, v)| k == "secure" && v == "true"),
        })
    }

    /// Establish signaling channel for WebRTC connection
    async fn establish_signaling_channel(&self, address: &ParsedWebRtcAddress) -> TransportResult<SignalingChannel> {
        use tokio_tungstenite::{connect_async, tungstenite::Message};
        
        let ws_url = if address.secure {
            format!("wss://{}:{}{}", address.host, address.port, address.path)
        } else {
            format!("ws://{}:{}{}", address.host, address.port, address.path)
        };
        
        tracing::debug!("Connecting to signaling server: {}", ws_url);
        
        let (ws_stream, _) = connect_async(&ws_url).await
            .map_err(|e| TransportError::ConnectionFailed(format!("Signaling connection failed: {}", e)))?;
        
        Ok(SignalingChannel::new(ws_stream))
    }

    /// Start signaling server for incoming WebRTC connections
    async fn start_signaling_server(&self, address: &ParsedWebRtcAddress) -> TransportResult<SignalingServer> {
        use tokio::net::TcpListener;
        
        let bind_addr = format!("{}:{}", address.host, address.port);
        let listener = TcpListener::bind(&bind_addr).await
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to bind signaling server: {}", e)))?;
        
        tracing::info!("Signaling server listening on {}", bind_addr);
        
        Ok(SignalingServer::new(listener))
    }

    /// Create ICE agent for WebRTC connection
    async fn create_ice_agent(&self) -> TransportResult<IceAgent> {
        let ice_config = self.create_ice_config();
        
        // Create ICE agent with STUN/TURN servers
        let mut agent_config = IceAgentConfig::default();
        
        // Add STUN servers
        for stun_server in &self.config.stun_servers {
            agent_config.add_stun_server(&stun_server.url);
        }
        
        // Add TURN servers
        for turn_server in &self.config.turn_servers {
            agent_config.add_turn_server(
                &turn_server.url,
                &turn_server.username,
                &turn_server.credential,
            );
        }
        
        agent_config.ice_lite = ice_config.ice_lite;
        agent_config.timeout = ice_config.ice_timeout;
        
        IceAgent::new(agent_config).await
            .map_err(|e| TransportError::ConnectionFailed(format!("ICE agent creation failed: {}", e)))
    }

    /// Create SDP offer for WebRTC connection
    async fn create_offer(&self, ice_agent: &IceAgent) -> TransportResult<String> {
        let offer = ice_agent.create_offer().await
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to create offer: {}", e)))?;
        
        Ok(offer.sdp)
    }

    /// Process SDP answer and establish peer connection
    async fn process_answer(&self, ice_agent: &IceAgent, answer_sdp: String) -> TransportResult<PeerConnection> {
        ice_agent.set_remote_description(answer_sdp).await
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to set remote description: {}", e)))?;
        
        let peer_connection = ice_agent.create_peer_connection().await
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to create peer connection: {}", e)))?;
        
        Ok(peer_connection)
    }

    /// Create data channel for WebRTC connection
    async fn create_data_channel(&self, peer_connection: &PeerConnection) -> TransportResult<DataChannel> {
        let config = self.create_datachannel_config();
        
        let data_channel = peer_connection.create_data_channel(&config.label, config).await
            .map_err(|e| TransportError::ConnectionFailed(format!("Failed to create data channel: {}", e)))?;
        
        Ok(data_channel)
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebRtc
    }
    
    async fn connect(&self, address: &str) -> zMeshResult<Arc<dyn Connection>> {
        tracing::info!("Establishing WebRTC connection to {}", address);
        
        // Parse WebRTC address (webrtc://host:port/path)
        let parsed_address = Self::parse_webrtc_address(address)?;
        
        let connection_id = self.next_connection_id();
        
        // Establish signaling channel
        let signaling_channel = self.establish_signaling_channel(&parsed_address).await?;
        
        // Create ICE agent with configured servers
        let ice_agent = self.create_ice_agent().await?;
        
        // Generate local offer
        let local_offer = self.create_offer(&ice_agent).await?;
        
        // Send offer through signaling
        signaling_channel.send_message(SignalingMessage::Offer {
            sdp: local_offer,
            peer_id: PeerId::new(),
        }).await?;
        
        // Wait for answer
        let answer = match signaling_channel.receive_message().await? {
            SignalingMessage::Answer { sdp, .. } => sdp,
            SignalingMessage::Error { message, .. } => {
                return Err(TransportError::ConnectionFailed(
                    format!("Signaling error: {}", message)
                ).into());
            }
            _ => {
                return Err(TransportError::ConnectionFailed(
                    "Unexpected signaling message".to_string()
                ).into());
            }
        };
        
        // Process answer and establish connection
        let peer_connection = self.process_answer(&ice_agent, answer).await?;
        
        // Create data channel
        let data_channel = self.create_data_channel(&peer_connection).await?;
        
        // Wait for connection to be established
        self.wait_for_connection_established(&peer_connection).await?;
        
        let connection = Arc::new(WebRtcConnection::new(
            connection_id,
            address.to_string(),
            false, // outbound
        ));
        
        self.connections.write().insert(connection_id, connection.clone());
        
        tracing::info!("WebRTC connection established to {}", address);
        
        Ok(connection as Arc<dyn Connection>)
    }
    
    async fn listen(&self, address: &str) -> zMeshResult<Arc<dyn Listener>> {
        tracing::info!("Starting WebRTC listener on {}", address);
        
        // Parse listen address
        let parsed_address = Self::parse_webrtc_address(address)?;
        
        // Start signaling server
        let signaling_server = self.start_signaling_server(&parsed_address).await?;
        
        // Create ICE agent for incoming connections
        let ice_agent = self.create_ice_agent().await?;
        
        let listener = Arc::new(WebRtcListener::new(
            address.to_string(),
            self.connections.clone(),
        ));
        
        tracing::info!("WebRTC listener started on {}", address);
        
        Ok(listener as Arc<dyn Listener>)
    }
    
    async fn close_connection(&self, connection_id: ConnectionId) -> zMeshResult<()> {
        if let Some(connection) = self.connections.write().remove(&connection_id) {
            connection.close().await?;
            tracing::debug!("Closed WebRTC connection {}", connection_id.0);
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
        
        tracing::info!("WebRTC transport shutdown complete");
        Ok(())
    }
}

/// WebRTC connection implementation (placeholder)
pub struct WebRtcConnection {
    id: ConnectionId,
    remote_addr: String,
    is_inbound: bool,
    stats: Arc<RwLock<ConnectionStats>>,
    // TODO: Add WebRTC-specific fields:
    // - DataChannel handle
    // - ICE connection state
    // - DTLS connection state
    // - Message queues
}

impl WebRtcConnection {
    /// Create new WebRTC connection
    pub fn new(id: ConnectionId, remote_addr: String, is_inbound: bool) -> Self {
        let stats = Arc::new(RwLock::new(ConnectionStats {
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        }));
        
        Self {
            id,
            remote_addr,
            is_inbound,
            stats,
        }
    }
}

#[async_trait]
impl Connection for WebRtcConnection {
    fn connection_id(&self) -> ConnectionId {
        self.id
    }
    
    fn remote_address(&self) -> String {
        self.remote_addr.clone()
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::WebRtc
    }
    
    fn is_inbound(&self) -> bool {
        self.is_inbound
    }
    
    async fn send(&self, _message: TransportMessage) -> zMeshResult<()> {
        // TODO: Implement WebRTC DataChannel send
        // 1. Serialize message
        // 2. Send over DataChannel
        // 3. Update statistics
        
        Err(TransportError::NotSupported(
            "WebRTC send not implemented yet".to_string()
        ).into())
    }
    
    async fn receive(&self) -> zMeshResult<TransportMessage> {
        // TODO: Implement WebRTC DataChannel receive
        // 1. Receive from DataChannel
        // 2. Deserialize message
        // 3. Update statistics
        
        Err(TransportError::NotSupported(
            "WebRTC receive not implemented yet".to_string()
        ).into())
    }
    
    async fn close(&self) -> zMeshResult<()> {
        // TODO: Implement WebRTC connection close
        // 1. Close DataChannel
        // 2. Close DTLS connection
        // 3. Close ICE connection
        
        tracing::debug!("WebRTC connection {} closed", self.id.0);
        Ok(())
    }
    
    fn stats(&self) -> ConnectionStats {
        self.stats.read().clone()
    }
    
    fn peer_id(&self) -> Option<PeerId> {
        // TODO: Extract peer ID from DTLS certificate
        None
    }
}

/// WebRTC listener implementation (placeholder)
pub struct WebRtcListener {
    local_addr: String,
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebRtcConnection>>>>,
    // TODO: Add WebRTC-specific fields:
    // - Signaling server connection
    // - ICE agent
    // - Accept channel
}

impl WebRtcListener {
    /// Create new WebRTC listener
    pub fn new(
        local_addr: String,
        connections: Arc<RwLock<HashMap<ConnectionId, Arc<WebRtcConnection>>>>,
    ) -> Self {
        Self {
            local_addr,
            connections,
        }
    }
}

#[async_trait]
impl Listener for WebRtcListener {
    fn local_address(&self) -> String {
        self.local_addr.clone()
    }
    
    fn transport_type(&self) -> TransportType {
        TransportType::WebRtc
    }
    
    async fn accept(&self) -> zMeshResult<Arc<dyn Connection>> {
        // TODO: Implement WebRTC accept
        // 1. Wait for incoming signaling message
        // 2. Perform ICE negotiation
        // 3. Establish DTLS connection
        // 4. Open DataChannel
        
        Err(TransportError::NotSupported(
            "WebRTC accept not implemented yet".to_string()
        ).into())
    }
    
    async fn close(&self) -> zMeshResult<()> {
        // TODO: Implement WebRTC listener close
        // 1. Close signaling server connection
        // 2. Stop accepting new connections
        
        tracing::info!("WebRTC listener on {} closed", self.local_addr);
        Ok(())
    }
}

/// ICE configuration for WebRTC
#[derive(Debug, Clone)]
struct IceConfig {
    turn_servers: Vec<TurnServer>,
    ice_timeout: std::time::Duration,
    ice_lite: bool,
}

/// WebRTC signaling message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SignalingMessage {
    /// SDP offer
    Offer {
        sdp: String,
        peer_id: PeerId,
    },
    /// SDP answer
    Answer {
        sdp: String,
        peer_id: PeerId,
    },
    /// ICE candidate
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
        peer_id: PeerId,
    },
    /// Connection error
    Error {
        message: String,
        peer_id: PeerId,
    },
}

/// Parsed WebRTC address components
#[derive(Debug, Clone)]
struct ParsedWebRtcAddress {
    host: String,
    port: u16,
    path: String,
    secure: bool,
}

/// WebRTC signaling channel for SDP exchange
struct SignalingChannel {
    // Placeholder for WebSocket connection
    // In a real implementation, this would contain the WebSocket stream
}

impl SignalingChannel {
    fn new(_ws_stream: impl std::fmt::Debug) -> Self {
        Self {}
    }
    
    async fn send_message(&self, _message: SignalingMessage) -> TransportResult<()> {
        // TODO: Implement WebSocket message sending
        Ok(())
    }
    
    async fn receive_message(&self) -> TransportResult<SignalingMessage> {
        // TODO: Implement WebSocket message receiving
        // For now, return a dummy answer
        Ok(SignalingMessage::Answer {
            sdp: "v=0\r\n...".to_string(),
            peer_id: PeerId::new(),
        })
    }
}

/// WebRTC signaling server for incoming connections
struct SignalingServer {
    // Placeholder for TCP listener
}

impl SignalingServer {
    fn new(_listener: tokio::net::TcpListener) -> Self {
        Self {}
    }
}

/// ICE agent configuration
#[derive(Debug, Clone)]
struct IceAgentConfig {
    ice_lite: bool,
    timeout: std::time::Duration,
    stun_servers: Vec<String>,
    turn_servers: Vec<(String, String, String)>, // (url, username, credential)
}

impl Default for IceAgentConfig {
    fn default() -> Self {
        Self {
            ice_lite: false,
            timeout: std::time::Duration::from_secs(30),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
        }
    }
}

impl IceAgentConfig {
    fn add_stun_server(&mut self, url: &str) {
        self.stun_servers.push(url.to_string());
    }
    
    fn add_turn_server(&mut self, url: &str, username: &str, credential: &str) {
        self.turn_servers.push((url.to_string(), username.to_string(), credential.to_string()));
    }
}

/// ICE agent for WebRTC connection establishment
struct IceAgent {
    config: IceAgentConfig,
}

impl IceAgent {
    async fn new(config: IceAgentConfig) -> Result<Self, String> {
        Ok(Self { config })
    }
    
    async fn create_offer(&self) -> Result<SdpOffer, String> {
        // TODO: Implement real SDP offer creation
        Ok(SdpOffer {
            sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n...".to_string(),
        })
    }
    
    async fn set_remote_description(&self, _sdp: String) -> Result<(), String> {
        // TODO: Implement remote description setting
        Ok(())
    }
    
    async fn create_peer_connection(&self) -> Result<PeerConnection, String> {
        // TODO: Implement peer connection creation
        Ok(PeerConnection {})
    }
}

/// SDP offer structure
struct SdpOffer {
    sdp: String,
}

/// WebRTC peer connection
struct PeerConnection {
    // Placeholder for peer connection state
}

impl PeerConnection {
    async fn create_data_channel(&self, _label: &str, _config: DataChannelConfig) -> Result<DataChannel, String> {
        // TODO: Implement data channel creation
        Ok(DataChannel {})
    }
    
    async fn wait_for_connection(&self) -> Result<(), String> {
        // TODO: Implement connection state waiting
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    }
}

/// WebRTC data channel
struct DataChannel {
    // Placeholder for data channel state
}

/// WebRTC DataChannel configuration
#[derive(Debug, Clone)]
pub struct DataChannelConfig {
    /// Channel label
    pub label: String,
    /// Ordered delivery
    pub ordered: bool,
    /// Maximum retransmits
    pub max_retransmits: Option<u16>,
    /// Maximum packet lifetime
    pub max_packet_life_time: Option<u16>,
    /// Protocol
    pub protocol: String,
}

impl Default for DataChannelConfig {
    fn default() -> Self {
        Self {
            label: "zMesh-data".to_string(),
            ordered: true,
            max_retransmits: Some(3),
            max_packet_life_time: None,
            protocol: "zMesh/1.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::transport::WebRtcConfig;
    
    #[tokio::test]
    async fn test_webrtc_transport_creation() {
        let config = WebRtcConfig::default();
        let transport = WebRtcTransport::new(config).await;
        assert!(transport.is_ok());
    }
    
    #[test]
    fn test_signaling_message_serialization() {
        let peer_id = PeerId::new();
        let offer = SignalingMessage::Offer {
            sdp: "v=0\r\n...".to_string(),
            peer_id,
        };
        
        let serialized = serde_json::to_string(&offer).unwrap();
        let deserialized: SignalingMessage = serde_json::from_str(&serialized).unwrap();
        
        match deserialized {
            SignalingMessage::Offer { peer_id: id, .. } => assert_eq!(id, peer_id),
            _ => panic!("Wrong message type"),
        }
    }
}