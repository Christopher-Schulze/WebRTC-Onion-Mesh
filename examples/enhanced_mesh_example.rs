//! Example demonstrating the enhanced mesh networking with traffic caching and multi-path distribution
//!
//! This example shows how to use the improved cache system for internet traffic chunks
//! distributed over multiple network paths.

use zMesh_core::{
    mesh_integration::{EnhancedMeshNode, EnhancedMeshBuilder},
    traffic_cache::{TrafficType, DistributionStrategy},
    peer::PeerId,
    error::Result,
};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Starting Enhanced Mesh Network Example");
    
    // Create enhanced mesh node with custom configuration
    let node_id = PeerId::random();
    let mut mesh_node = EnhancedMeshBuilder::new()
        .cache_size(50 * 1024 * 1024) // 50MB cache
        .max_paths(3) // Use up to 3 paths for distribution
        .distribution_strategy(DistributionStrategy::Adaptive)
        .enable_proactive_seeding(true)
        .build(node_id);
    
    println!("📡 Node ID: {}", node_id);
    
    // Start the mesh node
    mesh_node.start().await?;
    println!("✅ Enhanced mesh node started successfully");
    
    // Simulate internet traffic processing
    println!("\n🌐 Simulating Internet Traffic Processing...");
    
    // Simulate different types of traffic
    let traffic_scenarios = vec![
        ("Web browsing packets", TrafficType::WebBrowsing, 100),
        ("Video streaming chunks", TrafficType::Streaming, 50),
        ("File transfer blocks", TrafficType::FileTransfer, 25),
        ("Real-time communication", TrafficType::Realtime, 200),
    ];
    
    for (description, traffic_type, packet_count) in traffic_scenarios {
        println!("\n📦 Processing: {}", description);
        
        for i in 0..packet_count {
            // Generate simulated packet data
            let packet_data = generate_packet_data(traffic_type.clone(), i);
            let flow_id = match traffic_type {
                TrafficType::WebBrowsing => 1001,
                TrafficType::Streaming => 2001,
                TrafficType::FileTransfer => 3001,
                TrafficType::Realtime => 4001,
                _ => 5001,
            };
            
            // Process the chunk through the enhanced mesh
            mesh_node.process_chunk(packet_data, flow_id, i as u32).await?;
            
            // Small delay to simulate realistic traffic patterns
            if i % 10 == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        }
        
        // Display current metrics
        let metrics = mesh_node.get_metrics();
        println!("   📊 Cache hit rate: {:.2}%", metrics.cache_hit_rate * 100.0);
        println!("   📈 Packets processed: {}", metrics.packets_processed);
        println!("   ⚡ Avg path latency: {:?}", metrics.avg_path_latency);
        println!("   🎯 Multi-path efficiency: {:.2}%", metrics.multipath_efficiency * 100.0);
    }
    
    // Demonstrate cache warming and proactive seeding
    println!("\n🔥 Demonstrating Cache Warming...");
    
    // Simulate popular content being accessed multiple times
    let popular_flow_id = 9999;
    for i in 0..10 {
        let popular_data = generate_popular_content(i);
        
        // Access the same content multiple times to increase popularity
        for _ in 0..5 {
            mesh_node.process_chunk(popular_data.clone(), popular_flow_id, i as u32).await?;
            sleep(Duration::from_millis(5)).await;
        }
    }
    
    // Wait for proactive seeding to kick in
    println!("⏳ Waiting for proactive seeding...");
    sleep(Duration::from_secs(35)).await;
    
    // Final metrics
    let final_metrics = mesh_node.get_metrics();
    println!("\n📊 Final Performance Metrics:");
    println!("   🎯 Total packets processed: {}", final_metrics.packets_processed);
    println!("   💾 Cache hit rate: {:.2}%", final_metrics.cache_hit_rate * 100.0);
    println!("   ⚡ Average path latency: {:?}", final_metrics.avg_path_latency);
    println!("   🚀 Multi-path efficiency: {:.2}%", final_metrics.multipath_efficiency * 100.0);
    println!("   ✅ Successful deliveries: {}", final_metrics.successful_deliveries);
    println!("   ❌ Failed deliveries: {}", final_metrics.failed_deliveries);
    
    if final_metrics.successful_deliveries > 0 {
        let success_rate = final_metrics.successful_deliveries as f64 / 
            (final_metrics.successful_deliveries + final_metrics.failed_deliveries) as f64;
        println!("   📈 Overall success rate: {:.2}%", success_rate * 100.0);
    }
    
    // Demonstrate path bandwidth usage
    if !final_metrics.path_bandwidth_usage.is_empty() {
        println!("\n🛣️  Path Bandwidth Usage:");
        for (path_id, usage) in &final_metrics.path_bandwidth_usage {
            println!("   Path {}: {:.2}% utilization", path_id, usage * 100.0);
        }
    }
    
    // Stop the mesh node
    println!("\n🛑 Stopping enhanced mesh node...");
    mesh_node.stop().await;
    println!("✅ Enhanced mesh node stopped successfully");
    
    Ok(())
}

/// Generate simulated packet data based on traffic type
fn generate_packet_data(traffic_type: TrafficType, sequence: usize) -> Vec<u8> {
    let base_size = match traffic_type {
        TrafficType::Realtime => 160,      // Small voice packets
        TrafficType::WebBrowsing => 1400,  // Typical web packet
        TrafficType::Streaming => 8192,    // Video chunk
        TrafficType::FileTransfer => 16384, // Large file block
        TrafficType::BackgroundSync => 4096, // Medium sync block
    };
    
    let mut data = vec![0u8; base_size];
    
    // Fill with some pattern based on sequence
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((sequence + i) % 256) as u8;
    }
    
    // Add traffic type identifier
    let type_id = match traffic_type {
        TrafficType::Realtime => 0x01,
        TrafficType::WebBrowsing => 0x02,
        TrafficType::Streaming => 0x03,
        TrafficType::FileTransfer => 0x04,
        TrafficType::BackgroundSync => 0x05,
    };
    
    if !data.is_empty() {
        data[0] = type_id;
    }
    
    data
}

/// Generate popular content that will be cached and seeded
fn generate_popular_content(sequence: usize) -> Vec<u8> {
    let mut data = vec![0xAA; 2048]; // Popular content marker
    
    // Add sequence information
    let seq_bytes = (sequence as u32).to_be_bytes();
    if data.len() >= 4 {
        data[1..5].copy_from_slice(&seq_bytes);
    }
    
    data
}

/// Demonstrate advanced cache strategies
async fn demonstrate_cache_strategies() {
    println!("\n🧠 Demonstrating Advanced Cache Strategies...");
    
    // This would show:
    // 1. Popularity-based caching
    // 2. Access pattern recognition
    // 3. Predictive pre-loading
    // 4. Geographic distribution
    // 5. Load balancing across paths
    
    println!("   🎯 Popularity-based caching: Active");
    println!("   🔍 Access pattern recognition: Learning");
    println!("   🔮 Predictive pre-loading: Enabled");
    println!("   🌍 Geographic distribution: Optimizing");
    println!("   ⚖️  Load balancing: Adaptive");
}

/// Show distributed hash table operations
async fn demonstrate_dht_operations() {
    println!("\n🗂️  Demonstrating DHT-like Chunk Location Service...");
    
    // This would show:
    // 1. Chunk location discovery
    // 2. Peer capability matching
    // 3. Distributed cache coordination
    // 4. Fault tolerance
    
    println!("   🔍 Chunk location discovery: Active");
    println!("   🤝 Peer capability matching: Optimized");
    println!("   🔄 Distributed cache coordination: Synchronized");
    println!("   🛡️  Fault tolerance: Resilient");
}