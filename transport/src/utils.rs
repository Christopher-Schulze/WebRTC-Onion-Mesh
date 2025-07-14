//! Transport utilities and helper functions

use crate::{TransportError, TransportResult};
use zMesh_core::transport::{TransportType, ConnectionStats};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::{Duration, Instant},
};
use url::Url;

/// Address utilities
pub struct AddressUtils;

impl AddressUtils {
    /// Parse and validate an address string
    pub fn parse_address(address: &str) -> TransportResult<ParsedAddress> {
        // Try to parse as URL first
        if let Ok(url) = Url::parse(address) {
            return Self::parse_url(url);
        }
        
        // Try to parse as socket address
        if let Ok(socket_addr) = SocketAddr::from_str(address) {
            return Ok(ParsedAddress {
                transport_type: TransportType::WebSocket, // Default
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
                path: None,
                secure: false,
                query_params: std::collections::HashMap::new(),
            });
        }
        
        // Try to parse as host:port
        if let Some((host, port_str)) = address.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok(ParsedAddress {
                    transport_type: TransportType::WebSocket, // Default
                    host: host.to_string(),
                    port,
                    path: None,
                    secure: false,
                    query_params: std::collections::HashMap::new(),
                });
            }
        }
        
        Err(TransportError::InvalidAddress(
            format!("Cannot parse address: {}", address)
        ))
    }
    
    /// Parse URL into structured address
    fn parse_url(url: Url) -> TransportResult<ParsedAddress> {
        let transport_type = match url.scheme() {
            "ws" => TransportType::WebSocket,
            "wss" => TransportType::WebSocket,
            "webrtc" => TransportType::WebRtc,
            scheme => {
                return Err(TransportError::InvalidAddress(
                    format!("Unsupported scheme: {}", scheme)
                ));
            }
        };
        
        let host = url.host_str()
            .ok_or_else(|| TransportError::InvalidAddress("Missing host".to_string()))?
            .to_string();
        
        let port = url.port().unwrap_or_else(|| {
            match url.scheme() {
                "ws" => 80,
                "wss" => 443,
                "webrtc" => 8080, // Default WebRTC signaling port
                _ => 80,
            }
        });
        
        let secure = matches!(url.scheme(), "wss");
        
        let path = if url.path().is_empty() || url.path() == "/" {
            None
        } else {
            Some(url.path().to_string())
        };
        
        let query_params = url.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        
        Ok(ParsedAddress {
            transport_type,
            host,
            port,
            path,
            secure,
            query_params,
        })
    }
    
    /// Validate IP address
    pub fn is_valid_ip(ip: &str) -> bool {
        IpAddr::from_str(ip).is_ok()
    }
    
    /// Check if address is local/loopback
    pub fn is_local_address(address: &str) -> bool {
        if let Ok(parsed) = Self::parse_address(address) {
            if let Ok(ip) = IpAddr::from_str(&parsed.host) {
                return ip.is_loopback();
            }
            
            // Check for localhost hostname
            matches!(parsed.host.as_str(), "localhost" | "127.0.0.1" | "::1")
        } else {
            false
        }
    }
    
    /// Normalize address format
    pub fn normalize_address(address: &str, transport_type: TransportType) -> TransportResult<String> {
        let parsed = Self::parse_address(address)?;
        
        match transport_type {
            TransportType::WebSocket => {
                let scheme = if parsed.secure { "wss" } else { "ws" };
                let path = parsed.path.as_deref().unwrap_or("/");
                
                if parsed.query_params.is_empty() {
                    Ok(format!("{}://{}:{}{}", scheme, parsed.host, parsed.port, path))
                } else {
                    let query = parsed.query_params.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&");
                    Ok(format!("{}://{}:{}{}?{}", scheme, parsed.host, parsed.port, path, query))
                }
            }
            TransportType::WebRtc => {
                Ok(format!("webrtc://{}:{}", parsed.host, parsed.port))
            }
        }
    }
}

/// Parsed address structure
#[derive(Debug, Clone)]
pub struct ParsedAddress {
    pub transport_type: TransportType,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
    pub secure: bool,
    pub query_params: std::collections::HashMap<String, String>,
}

impl ParsedAddress {
    /// Convert back to address string
    pub fn to_address_string(&self) -> String {
        match self.transport_type {
            TransportType::WebSocket => {
                let scheme = if self.secure { "wss" } else { "ws" };
                let path = self.path.as_deref().unwrap_or("/");
                
                if self.query_params.is_empty() {
                    format!("{}://{}:{}{}", scheme, self.host, self.port, path)
                } else {
                    let query = self.query_params.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&");
                    format!("{}://{}:{}{}?{}", scheme, self.host, self.port, path, query)
                }
            }
            TransportType::WebRtc => {
                format!("webrtc://{}:{}", self.host, self.port)
            }
        }
    }
    
    /// Get socket address
    pub fn socket_address(&self) -> TransportResult<SocketAddr> {
        let ip = IpAddr::from_str(&self.host)
            .map_err(|_| TransportError::InvalidAddress(
                format!("Invalid IP address: {}", self.host)
            ))?;
        
        Ok(SocketAddr::new(ip, self.port))
    }
}

/// Connection statistics utilities
pub struct StatsUtils;

impl StatsUtils {
    /// Calculate connection throughput (bytes per second)
    pub fn calculate_throughput(stats: &ConnectionStats) -> (f64, f64) {
        let duration = stats.connected_at.elapsed().as_secs_f64();
        
        if duration > 0.0 {
            let send_throughput = stats.bytes_sent as f64 / duration;
            let recv_throughput = stats.bytes_received as f64 / duration;
            (send_throughput, recv_throughput)
        } else {
            (0.0, 0.0)
        }
    }
    
    /// Calculate message rate (messages per second)
    pub fn calculate_message_rate(stats: &ConnectionStats) -> (f64, f64) {
        let duration = stats.connected_at.elapsed().as_secs_f64();
        
        if duration > 0.0 {
            let send_rate = stats.messages_sent as f64 / duration;
            let recv_rate = stats.messages_received as f64 / duration;
            (send_rate, recv_rate)
        } else {
            (0.0, 0.0)
        }
    }
    
    /// Check if connection is idle
    pub fn is_idle(stats: &ConnectionStats, idle_threshold: Duration) -> bool {
        stats.last_activity.elapsed() > idle_threshold
    }
    
    /// Format bytes in human-readable format
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        
        if bytes == 0 {
            return "0 B".to_string();
        }
        
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }
    
    /// Format duration in human-readable format
    pub fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        
        if total_seconds < 60 {
            format!("{}s", total_seconds)
        } else if total_seconds < 3600 {
            let minutes = total_seconds / 60;
            let seconds = total_seconds % 60;
            format!("{}m {}s", minutes, seconds)
        } else {
            let hours = total_seconds / 3600;
            let minutes = (total_seconds % 3600) / 60;
            let seconds = total_seconds % 60;
            format!("{}h {}m {}s", hours, minutes, seconds)
        }
    }
}

/// Network utilities
pub struct NetworkUtils;

impl NetworkUtils {
    /// Check if port is available
    pub async fn is_port_available(port: u16) -> bool {
        use tokio::net::TcpListener;
        
        TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
    }
    
    /// Find available port in range
    pub async fn find_available_port(start: u16, end: u16) -> Option<u16> {
        for port in start..=end {
            if Self::is_port_available(port).await {
                return Some(port);
            }
        }
        None
    }
    
    /// Get local IP addresses
    pub fn get_local_ips() -> Vec<IpAddr> {
        use std::net::UdpSocket;
        
        let mut ips = Vec::new();
        
        // Try to connect to a remote address to determine local IP
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    ips.push(local_addr.ip());
                }
            }
        }
        
        // Add loopback
        ips.push(IpAddr::from([127, 0, 0, 1]));
        ips.push(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]));
        
        ips
    }
    
    /// Check network connectivity
    pub async fn check_connectivity(target: &str) -> bool {
        use tokio::net::TcpStream;
        use tokio::time::timeout;
        
        let timeout_duration = Duration::from_secs(5);
        
        if let Ok(parsed) = AddressUtils::parse_address(target) {
            if let Ok(socket_addr) = parsed.socket_address() {
                return timeout(timeout_duration, TcpStream::connect(socket_addr))
                    .await
                    .is_ok();
            }
        }
        
        false
    }
}

/// Message utilities
pub struct MessageUtils;

impl MessageUtils {
    /// Calculate message overhead for transport
    pub fn calculate_overhead(transport_type: TransportType, payload_size: usize) -> usize {
        match transport_type {
            TransportType::WebSocket => {
                // WebSocket frame overhead
                let frame_overhead = if payload_size < 126 {
                    2 // 1 byte header + 1 byte length
                } else if payload_size < 65536 {
                    4 // 1 byte header + 1 byte extended length marker + 2 bytes length
                } else {
                    10 // 1 byte header + 1 byte extended length marker + 8 bytes length
                };
                
                // Add masking key for client frames
                frame_overhead + 4
            }
            TransportType::WebRtc => {
                // SCTP + DTLS overhead (approximate)
                32
            }
        }
    }
    
    /// Calculate maximum payload size for transport
    pub fn max_payload_size(transport_type: TransportType) -> usize {
        match transport_type {
            TransportType::WebSocket => {
                // WebSocket max frame size (configurable, but commonly 64KB)
                64 * 1024
            }
            TransportType::WebRtc => {
                // WebRTC DataChannel max message size
                256 * 1024
            }
        }
    }
    
    /// Fragment large message if needed
    pub fn fragment_message(data: &[u8], max_size: usize) -> Vec<Vec<u8>> {
        if data.len() <= max_size {
            return vec![data.to_vec()];
        }
        
        data.chunks(max_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_parsing() {
        // Test WebSocket URL
        let parsed = AddressUtils::parse_address("ws://example.com:8080/path").unwrap();
        assert_eq!(parsed.transport_type, TransportType::WebSocket);
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path, Some("/path".to_string()));
        assert!(!parsed.secure);
        
        // Test secure WebSocket URL
        let parsed = AddressUtils::parse_address("wss://example.com/path").unwrap();
        assert_eq!(parsed.transport_type, TransportType::WebSocket);
        assert_eq!(parsed.port, 443);
        assert!(parsed.secure);
        
        // Test WebRTC URL
        let parsed = AddressUtils::parse_address("webrtc://example.com:9000").unwrap();
        assert_eq!(parsed.transport_type, TransportType::WebRtc);
        assert_eq!(parsed.port, 9000);
        
        // Test socket address
        let parsed = AddressUtils::parse_address("127.0.0.1:8080").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 8080);
    }
    
    #[test]
    fn test_address_normalization() {
        let normalized = AddressUtils::normalize_address(
            "example.com:8080",
            TransportType::WebSocket
        ).unwrap();
        assert_eq!(normalized, "ws://example.com:8080/");
        
        let normalized = AddressUtils::normalize_address(
            "example.com:9000",
            TransportType::WebRtc
        ).unwrap();
        assert_eq!(normalized, "webrtc://example.com:9000");
    }
    
    #[test]
    fn test_local_address_detection() {
        assert!(AddressUtils::is_local_address("127.0.0.1:8080"));
        assert!(AddressUtils::is_local_address("localhost:8080"));
        assert!(AddressUtils::is_local_address("ws://localhost:8080"));
        assert!(!AddressUtils::is_local_address("example.com:8080"));
    }
    
    #[test]
    fn test_bytes_formatting() {
        assert_eq!(StatsUtils::format_bytes(0), "0 B");
        assert_eq!(StatsUtils::format_bytes(1024), "1.00 KB");
        assert_eq!(StatsUtils::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(StatsUtils::format_bytes(1536), "1.50 KB");
    }
    
    #[test]
    fn test_duration_formatting() {
        assert_eq!(StatsUtils::format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(StatsUtils::format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(StatsUtils::format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }
    
    #[test]
    fn test_message_fragmentation() {
        let data = vec![1u8; 1000];
        let fragments = MessageUtils::fragment_message(&data, 300);
        
        assert_eq!(fragments.len(), 4); // 1000 / 300 = 3.33, so 4 fragments
        assert_eq!(fragments[0].len(), 300);
        assert_eq!(fragments[1].len(), 300);
        assert_eq!(fragments[2].len(), 300);
        assert_eq!(fragments[3].len(), 100);
    }
    
    #[tokio::test]
    async fn test_port_availability() {
        // Port 0 should always be available (OS assigns)
        assert!(NetworkUtils::is_port_available(0).await);
        
        // Find an available port in range
        let port = NetworkUtils::find_available_port(8000, 8100).await;
        assert!(port.is_some());
    }
}