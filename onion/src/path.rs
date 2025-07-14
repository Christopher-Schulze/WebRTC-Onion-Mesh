//! Path selection for onion routing
//! Implements intelligent path selection with configurable strategies

use crate::error::{OnionResult, PathError};
use crnet_core::peer::{PeerId, PeerInfo};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Path selection strategy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathStrategy {
    /// Random selection
    Random,
    /// Lowest latency path
    LowestLatency,
    /// Highest reliability path
    HighestReliability,
    /// Balanced (latency + reliability)
    Balanced,
    /// Geographic diversity
    GeographicDiversity,
    /// Network diversity (different ASNs)
    NetworkDiversity,
    /// Custom weighted selection
    Weighted,
}

impl Default for PathStrategy {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Path selection constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConstraints {
    /// Maximum total latency
    pub max_latency: Option<Duration>,
    /// Minimum reliability score (0.0 - 1.0)
    pub min_reliability: Option<f32>,
    /// Minimum bandwidth (bytes/sec)
    pub min_bandwidth: Option<u64>,
    /// Excluded countries (ISO country codes)
    pub excluded_countries: HashSet<String>,
    /// Excluded ASNs
    pub excluded_asns: HashSet<u32>,
    /// Excluded IP ranges
    pub excluded_ip_ranges: Vec<IpRange>,
    /// Require geographic diversity
    pub require_geo_diversity: bool,
    /// Require network diversity
    pub require_network_diversity: bool,
    /// Maximum hops from same country
    pub max_same_country: Option<usize>,
    /// Maximum hops from same ASN
    pub max_same_asn: Option<usize>,
    /// Minimum uptime
    pub min_uptime: Option<Duration>,
    /// Blacklisted peers
    pub blacklisted_peers: HashSet<PeerId>,
}

impl Default for PathConstraints {
    fn default() -> Self {
        Self {
            max_latency: Some(Duration::from_millis(2000)),
            min_reliability: Some(0.8),
            min_bandwidth: Some(1024 * 1024), // 1 MB/s
            excluded_countries: HashSet::new(),
            excluded_asns: HashSet::new(),
            excluded_ip_ranges: Vec::new(),
            require_geo_diversity: true,
            require_network_diversity: true,
            max_same_country: Some(1),
            max_same_asn: Some(1),
            min_uptime: Some(Duration::from_secs(3600)), // 1 hour
            blacklisted_peers: HashSet::new(),
        }
    }
}

/// IP address range for exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

impl IpRange {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.start, self.end, ip) {
            (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(ip)) => {
                let start_u32 = u32::from(*start);
                let end_u32 = u32::from(*end);
                let ip_u32 = u32::from(*ip);
                ip_u32 >= start_u32 && ip_u32 <= end_u32
            }
            (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(ip)) => {
                let start_u128 = u128::from(*start);
                let end_u128 = u128::from(*end);
                let ip_u128 = u128::from(*ip);
                ip_u128 >= start_u128 && ip_u128 <= end_u128
            }
            _ => false, // Mixed IP versions
        }
    }
}

/// Node information for path selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNode {
    /// Peer ID
    pub peer_id: PeerId,
    /// Peer information
    pub peer_info: PeerInfo,
    /// Node latency
    pub latency: Option<Duration>,
    /// Node reliability score (0.0 - 1.0)
    pub reliability: Option<f32>,
    /// Node bandwidth (bytes/sec)
    pub bandwidth: Option<u64>,
    /// Node uptime
    pub uptime: Option<Duration>,
    /// Geographic location (country code)
    pub country: Option<String>,
    /// Autonomous System Number
    pub asn: Option<u32>,
    /// IP address
    pub ip_address: Option<IpAddr>,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Node capabilities
    pub capabilities: HashSet<String>,
    /// Exit policy (for exit nodes)
    pub exit_policy: Option<ExitPolicy>,
}

/// Exit policy for exit nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPolicy {
    /// Allowed ports
    pub allowed_ports: HashSet<u16>,
    /// Blocked ports
    pub blocked_ports: HashSet<u16>,
    /// Allowed destinations
    pub allowed_destinations: Vec<String>,
    /// Blocked destinations
    pub blocked_destinations: Vec<String>,
}

/// Selected path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedPath {
    /// Path nodes in order
    pub nodes: Vec<PathNode>,
    /// Total estimated latency
    pub total_latency: Option<Duration>,
    /// Minimum reliability in path
    pub min_reliability: Option<f32>,
    /// Minimum bandwidth in path
    pub min_bandwidth: Option<u64>,
    /// Path selection strategy used
    pub strategy: PathStrategy,
    /// Path score (higher is better)
    pub score: f64,
    /// Path creation timestamp
    pub created_at: SystemTime,
}

/// Path selection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathStats {
    /// Total paths selected
    pub paths_selected: u64,
    /// Successful path builds
    pub successful_builds: u64,
    /// Failed path builds
    pub failed_builds: u64,
    /// Average path latency
    pub avg_latency: Option<Duration>,
    /// Average path reliability
    pub avg_reliability: Option<f32>,
    /// Strategy usage counts
    pub strategy_usage: HashMap<String, u64>,
}

/// Path selector implementation
pub struct PathSelector {
    /// Available nodes
    nodes: HashMap<PeerId, PathNode>,
    /// Path selection strategy
    strategy: PathStrategy,
    /// Path constraints
    constraints: PathConstraints,
    /// Selection statistics
    stats: PathStats,
    /// Random number generator
    rng: rand::rngs::ThreadRng,
}

impl PathSelector {
    /// Create a new path selector
    pub fn new(strategy: PathStrategy, constraints: PathConstraints) -> Self {
        Self {
            nodes: HashMap::new(),
            strategy,
            constraints,
            stats: PathStats::default(),
            rng: rand::thread_rng(),
        }
    }
    
    /// Add a node to the available nodes
    pub fn add_node(&mut self, node: PathNode) {
        self.nodes.insert(node.peer_id.clone(), node);
    }
    
    /// Remove a node from available nodes
    pub fn remove_node(&mut self, peer_id: &PeerId) {
        self.nodes.remove(peer_id);
    }
    
    /// Update node information
    pub fn update_node(&mut self, peer_id: &PeerId, update_fn: impl FnOnce(&mut PathNode)) {
        if let Some(node) = self.nodes.get_mut(peer_id) {
            update_fn(node);
        }
    }
    
    /// Get available node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    
    /// Select a path with the specified number of hops
    pub fn select_path(&mut self, hop_count: u8) -> OnionResult<SelectedPath> {
        if hop_count < 2 || hop_count > 3 {
            return Err(crate::error::OnionError::invalid_hop_count(hop_count));
        }
        
        // Filter suitable nodes
        let suitable_nodes = self.filter_suitable_nodes()?;
        
        if suitable_nodes.len() < hop_count as usize {
            return Err(PathError::InsufficientNodes {
                hops: hop_count as usize,
                available: suitable_nodes.len(),
            }.into());
        }
        
        // Select path based on strategy
        let selected_nodes = match self.strategy {
            PathStrategy::Random => self.select_random_path(&suitable_nodes, hop_count)?,
            PathStrategy::LowestLatency => self.select_lowest_latency_path(&suitable_nodes, hop_count)?,
            PathStrategy::HighestReliability => self.select_highest_reliability_path(&suitable_nodes, hop_count)?,
            PathStrategy::Balanced => self.select_balanced_path(&suitable_nodes, hop_count)?,
            PathStrategy::GeographicDiversity => self.select_geo_diverse_path(&suitable_nodes, hop_count)?,
            PathStrategy::NetworkDiversity => self.select_network_diverse_path(&suitable_nodes, hop_count)?,
            PathStrategy::Weighted => self.select_weighted_path(&suitable_nodes, hop_count)?,
        };
        
        // Validate the selected path
        self.validate_path(&selected_nodes)?;
        
        // Calculate path metrics
        let path = self.create_path_info(selected_nodes);
        
        // Update statistics
        self.update_stats(&path);
        
        Ok(path)
    }
    
    /// Filter nodes that meet the basic constraints
    fn filter_suitable_nodes(&self) -> OnionResult<Vec<&PathNode>> {
        let mut suitable_nodes = Vec::new();
        
        for node in self.nodes.values() {
            if self.is_node_suitable(node) {
                suitable_nodes.push(node);
            }
        }
        
        if suitable_nodes.is_empty() {
            return Err(PathError::NoSuitableNodes.into());
        }
        
        Ok(suitable_nodes)
    }
    
    /// Check if a node meets the basic constraints
    fn is_node_suitable(&self, node: &PathNode) -> bool {
        // Check blacklist
        if self.constraints.blacklisted_peers.contains(&node.peer_id) {
            return false;
        }
        
        // Check latency constraint
        if let (Some(max_latency), Some(node_latency)) = (self.constraints.max_latency, node.latency) {
            if node_latency > max_latency {
                return false;
            }
        }
        
        // Check reliability constraint
        if let (Some(min_reliability), Some(node_reliability)) = (self.constraints.min_reliability, node.reliability) {
            if node_reliability < min_reliability {
                return false;
            }
        }
        
        // Check bandwidth constraint
        if let (Some(min_bandwidth), Some(node_bandwidth)) = (self.constraints.min_bandwidth, node.bandwidth) {
            if node_bandwidth < min_bandwidth {
                return false;
            }
        }
        
        // Check uptime constraint
        if let (Some(min_uptime), Some(node_uptime)) = (self.constraints.min_uptime, node.uptime) {
            if node_uptime < min_uptime {
                return false;
            }
        }
        
        // Check country exclusion
        if let Some(country) = &node.country {
            if self.constraints.excluded_countries.contains(country) {
                return false;
            }
        }
        
        // Check ASN exclusion
        if let Some(asn) = node.asn {
            if self.constraints.excluded_asns.contains(&asn) {
                return false;
            }
        }
        
        // Check IP range exclusion
        if let Some(ip) = node.ip_address {
            for range in &self.constraints.excluded_ip_ranges {
                if range.contains(&ip) {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Select a random path
    fn select_random_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        let mut selected = Vec::new();
        let mut available: Vec<_> = nodes.iter().cloned().collect();
        
        for _ in 0..hop_count {
            if available.is_empty() {
                return Err(PathError::InsufficientNodes {
                    hops: hop_count as usize,
                    available: selected.len(),
                }.into());
            }
            
            let index = self.rng.gen_range(0..available.len());
            let node = available.remove(index);
            selected.push((*node).clone());
        }
        
        Ok(selected)
    }
    
    /// Select path with lowest total latency
    fn select_lowest_latency_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        // Sort nodes by latency
        let mut sorted_nodes: Vec<_> = nodes.iter()
            .filter(|node| node.latency.is_some())
            .collect();
        
        sorted_nodes.sort_by(|a, b| a.latency.cmp(&b.latency));
        
        if sorted_nodes.len() < hop_count as usize {
            return Err(PathError::InsufficientNodes {
                hops: hop_count as usize,
                available: sorted_nodes.len(),
            }.into());
        }
        
        let selected: Vec<PathNode> = sorted_nodes
            .into_iter()
            .take(hop_count as usize)
            .map(|node| (*node).clone())
            .collect();
        
        Ok(selected)
    }
    
    /// Select path with highest reliability
    fn select_highest_reliability_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        // Sort nodes by reliability (descending)
        let mut sorted_nodes: Vec<_> = nodes.iter()
            .filter(|node| node.reliability.is_some())
            .collect();
        
        sorted_nodes.sort_by(|a, b| b.reliability.partial_cmp(&a.reliability).unwrap_or(std::cmp::Ordering::Equal));
        
        if sorted_nodes.len() < hop_count as usize {
            return Err(PathError::InsufficientNodes {
                hops: hop_count as usize,
                available: sorted_nodes.len(),
            }.into());
        }
        
        let selected: Vec<PathNode> = sorted_nodes
            .into_iter()
            .take(hop_count as usize)
            .map(|node| (*node).clone())
            .collect();
        
        Ok(selected)
    }
    
    /// Select balanced path (latency + reliability)
    fn select_balanced_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        // Calculate balanced score for each node
        let mut scored_nodes: Vec<_> = nodes.iter()
            .filter_map(|node| {
                let latency_score = node.latency
                    .map(|lat| 1.0 - (lat.as_millis() as f64 / 5000.0).min(1.0))
                    .unwrap_or(0.5);
                
                let reliability_score = node.reliability
                    .map(|rel| rel as f64)
                    .unwrap_or(0.5);
                
                let bandwidth_score = node.bandwidth
                    .map(|bw| (bw as f64 / (10.0 * 1024.0 * 1024.0)).min(1.0))
                    .unwrap_or(0.5);
                
                // Weighted average: 30% latency, 40% reliability, 30% bandwidth
                let score = 0.3 * latency_score + 0.4 * reliability_score + 0.3 * bandwidth_score;
                
                Some((node, score))
            })
            .collect();
        
        // Sort by score (descending)
        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        if scored_nodes.len() < hop_count as usize {
            return Err(PathError::InsufficientNodes {
                hops: hop_count as usize,
                available: scored_nodes.len(),
            }.into());
        }
        
        let selected: Vec<PathNode> = scored_nodes
            .into_iter()
            .take(hop_count as usize)
            .map(|(node, _score)| (*node).clone())
            .collect();
        
        Ok(selected)
    }
    
    /// Select geographically diverse path
    fn select_geo_diverse_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        let mut selected = Vec::new();
        let mut used_countries = HashSet::new();
        let mut available: Vec<_> = nodes.iter().cloned().collect();
        
        for _ in 0..hop_count {
            // Filter nodes from unused countries
            let candidates: Vec<_> = available.iter()
                .filter(|node| {
                    if let Some(country) = &node.country {
                        !used_countries.contains(country)
                    } else {
                        true // Allow nodes without country info
                    }
                })
                .cloned()
                .collect();
            
            if candidates.is_empty() {
                // If no diverse candidates, fall back to any available
                if available.is_empty() {
                    return Err(PathError::InsufficientNodes {
                        hops: hop_count as usize,
                        available: selected.len(),
                    }.into());
                }
                
                let index = self.rng.gen_range(0..available.len());
                let node = available.remove(index);
                selected.push((*node).clone());
            } else {
                // Select from diverse candidates
                let index = self.rng.gen_range(0..candidates.len());
                let node = candidates[index];
                
                if let Some(country) = &node.country {
                    used_countries.insert(country.clone());
                }
                
                selected.push((*node).clone());
                available.retain(|n| n.peer_id != node.peer_id);
            }
        }
        
        Ok(selected)
    }
    
    /// Select network diverse path (different ASNs)
    fn select_network_diverse_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        let mut selected = Vec::new();
        let mut used_asns = HashSet::new();
        let mut available: Vec<_> = nodes.iter().cloned().collect();
        
        for _ in 0..hop_count {
            // Filter nodes from unused ASNs
            let candidates: Vec<_> = available.iter()
                .filter(|node| {
                    if let Some(asn) = node.asn {
                        !used_asns.contains(&asn)
                    } else {
                        true // Allow nodes without ASN info
                    }
                })
                .cloned()
                .collect();
            
            if candidates.is_empty() {
                // If no diverse candidates, fall back to any available
                if available.is_empty() {
                    return Err(PathError::InsufficientNodes {
                        hops: hop_count as usize,
                        available: selected.len(),
                    }.into());
                }
                
                let index = self.rng.gen_range(0..available.len());
                let node = available.remove(index);
                selected.push((*node).clone());
            } else {
                // Select from diverse candidates
                let index = self.rng.gen_range(0..candidates.len());
                let node = candidates[index];
                
                if let Some(asn) = node.asn {
                    used_asns.insert(asn);
                }
                
                selected.push((*node).clone());
                available.retain(|n| n.peer_id != node.peer_id);
            }
        }
        
        Ok(selected)
    }
    
    /// Select weighted path (placeholder for custom weighting)
    fn select_weighted_path(&mut self, nodes: &[&PathNode], hop_count: u8) -> OnionResult<Vec<PathNode>> {
        // For now, use balanced selection as default weighted approach
        self.select_balanced_path(nodes, hop_count)
    }
    
    /// Validate the selected path meets all constraints
    fn validate_path(&self, nodes: &[PathNode]) -> OnionResult<()> {
        // Check total latency
        if let Some(max_latency) = self.constraints.max_latency {
            let total_latency: Duration = nodes.iter()
                .filter_map(|node| node.latency)
                .sum();
            
            if total_latency > max_latency {
                return Err(PathError::LatencyConstraintViolated {
                    latency: total_latency.as_millis() as u32,
                    max_latency: max_latency.as_millis() as u32,
                }.into());
            }
        }
        
        // Check minimum reliability
        if let Some(min_reliability) = self.constraints.min_reliability {
            let min_node_reliability = nodes.iter()
                .filter_map(|node| node.reliability)
                .fold(1.0, |acc, rel| acc.min(rel));
            
            if min_node_reliability < min_reliability {
                return Err(PathError::ReliabilityConstraintViolated {
                    reliability: min_node_reliability,
                    min_reliability,
                }.into());
            }
        }
        
        // Check geographic diversity
        if self.constraints.require_geo_diversity {
            let countries: HashSet<_> = nodes.iter()
                .filter_map(|node| node.country.as_ref())
                .collect();
            
            if countries.len() < nodes.len() {
                return Err(PathError::DiversityConstraintViolated {
                    constraint: "Geographic diversity required".to_string(),
                }.into());
            }
        }
        
        // Check network diversity
        if self.constraints.require_network_diversity {
            let asns: HashSet<_> = nodes.iter()
                .filter_map(|node| node.asn)
                .collect();
            
            if asns.len() < nodes.len() {
                return Err(PathError::DiversityConstraintViolated {
                    constraint: "Network diversity required".to_string(),
                }.into());
            }
        }
        
        Ok(())
    }
    
    /// Create path information from selected nodes
    fn create_path_info(&self, nodes: Vec<PathNode>) -> SelectedPath {
        let total_latency = nodes.iter()
            .filter_map(|node| node.latency)
            .reduce(|acc, lat| acc + lat);
        
        let min_reliability = nodes.iter()
            .filter_map(|node| node.reliability)
            .fold(1.0, |acc, rel| acc.min(rel));
        
        let min_bandwidth = nodes.iter()
            .filter_map(|node| node.bandwidth)
            .min();
        
        // Calculate path score (higher is better)
        let latency_score = total_latency
            .map(|lat| 1.0 - (lat.as_millis() as f64 / 5000.0).min(1.0))
            .unwrap_or(0.5);
        
        let reliability_score = if min_reliability > 0.0 {
            min_reliability as f64
        } else {
            0.5
        };
        
        let bandwidth_score = min_bandwidth
            .map(|bw| (bw as f64 / (10.0 * 1024.0 * 1024.0)).min(1.0))
            .unwrap_or(0.5);
        
        let score = 0.3 * latency_score + 0.4 * reliability_score + 0.3 * bandwidth_score;
        
        SelectedPath {
            nodes,
            total_latency,
            min_reliability: if min_reliability > 0.0 { Some(min_reliability) } else { None },
            min_bandwidth,
            strategy: self.strategy.clone(),
            score,
            created_at: SystemTime::now(),
        }
    }
    
    /// Update selection statistics
    fn update_stats(&mut self, path: &SelectedPath) {
        self.stats.paths_selected += 1;
        
        // Update average latency
        if let Some(latency) = path.total_latency {
            self.stats.avg_latency = Some(
                self.stats.avg_latency
                    .map(|avg| (avg + latency) / 2)
                    .unwrap_or(latency)
            );
        }
        
        // Update average reliability
        if let Some(reliability) = path.min_reliability {
            self.stats.avg_reliability = Some(
                self.stats.avg_reliability
                    .map(|avg| (avg + reliability) / 2.0)
                    .unwrap_or(reliability)
            );
        }
        
        // Update strategy usage
        let strategy_name = format!("{:?}", path.strategy);
        *self.stats.strategy_usage.entry(strategy_name).or_insert(0) += 1;
    }
    
    /// Get path selection statistics
    pub fn get_stats(&self) -> &PathStats {
        &self.stats
    }
    
    /// Update strategy
    pub fn set_strategy(&mut self, strategy: PathStrategy) {
        self.strategy = strategy;
    }
    
    /// Update constraints
    pub fn set_constraints(&mut self, constraints: PathConstraints) {
        self.constraints = constraints;
    }
    
    /// Get current strategy
    pub fn get_strategy(&self) -> &PathStrategy {
        &self.strategy
    }
    
    /// Get current constraints
    pub fn get_constraints(&self) -> &PathConstraints {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    fn create_test_node(id: &str, country: Option<&str>, asn: Option<u32>) -> PathNode {
        PathNode {
            peer_id: PeerId::new(id.to_string()),
            peer_info: PeerInfo::default(),
            latency: Some(Duration::from_millis(100)),
            reliability: Some(0.9),
            bandwidth: Some(10 * 1024 * 1024),
            uptime: Some(Duration::from_secs(7200)),
            country: country.map(|c| c.to_string()),
            asn,
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            last_seen: SystemTime::now(),
            capabilities: HashSet::new(),
            exit_policy: None,
        }
    }
    
    #[test]
    fn test_path_selector_creation() {
        let selector = PathSelector::new(
            PathStrategy::Balanced,
            PathConstraints::default(),
        );
        
        assert_eq!(selector.node_count(), 0);
        assert_eq!(selector.get_strategy(), &PathStrategy::Balanced);
    }
    
    #[test]
    fn test_node_management() {
        let mut selector = PathSelector::new(
            PathStrategy::Random,
            PathConstraints::default(),
        );
        
        let node = create_test_node("node1", Some("US"), Some(1234));
        let peer_id = node.peer_id.clone();
        
        selector.add_node(node);
        assert_eq!(selector.node_count(), 1);
        
        selector.remove_node(&peer_id);
        assert_eq!(selector.node_count(), 0);
    }
    
    #[test]
    fn test_path_selection_insufficient_nodes() {
        let mut selector = PathSelector::new(
            PathStrategy::Random,
            PathConstraints::default(),
        );
        
        // Add only one node
        selector.add_node(create_test_node("node1", Some("US"), Some(1234)));
        
        // Try to select 2-hop path
        let result = selector.select_path(2);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_path_selection_success() {
        let mut selector = PathSelector::new(
            PathStrategy::Random,
            PathConstraints::default(),
        );
        
        // Add sufficient nodes
        selector.add_node(create_test_node("node1", Some("US"), Some(1234)));
        selector.add_node(create_test_node("node2", Some("DE"), Some(5678)));
        selector.add_node(create_test_node("node3", Some("JP"), Some(9012)));
        
        // Select 2-hop path
        let result = selector.select_path(2);
        assert!(result.is_ok());
        
        let path = result.unwrap();
        assert_eq!(path.nodes.len(), 2);
        assert_eq!(path.strategy, PathStrategy::Random);
    }
    
    #[test]
    fn test_geographic_diversity() {
        let mut selector = PathSelector::new(
            PathStrategy::GeographicDiversity,
            PathConstraints::default(),
        );
        
        // Add nodes from different countries
        selector.add_node(create_test_node("node1", Some("US"), Some(1234)));
        selector.add_node(create_test_node("node2", Some("DE"), Some(5678)));
        selector.add_node(create_test_node("node3", Some("JP"), Some(9012)));
        
        let result = selector.select_path(3);
        assert!(result.is_ok());
        
        let path = result.unwrap();
        let countries: HashSet<_> = path.nodes.iter()
            .filter_map(|node| node.country.as_ref())
            .collect();
        
        // Should have 3 different countries
        assert_eq!(countries.len(), 3);
    }
    
    #[test]
    fn test_ip_range_contains() {
        let range = IpRange {
            start: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            end: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
        };
        
        assert!(range.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!range.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }
    
    #[test]
    fn test_invalid_hop_count() {
        let mut selector = PathSelector::new(
            PathStrategy::Random,
            PathConstraints::default(),
        );
        
        // Add sufficient nodes
        for i in 0..5 {
            selector.add_node(create_test_node(&format!("node{}", i), Some("US"), Some(1234 + i)));
        }
        
        // Test invalid hop counts
        assert!(selector.select_path(1).is_err());
        assert!(selector.select_path(4).is_err());
        
        // Test valid hop counts
        assert!(selector.select_path(2).is_ok());
        assert!(selector.select_path(3).is_ok());
    }
}