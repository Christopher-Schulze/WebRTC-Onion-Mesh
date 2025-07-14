//! Core traits and types for zMesh P2P overlay network
//!
//! This module provides the fundamental building blocks for the zMesh system:
//! - Transport abstraction for WebRTC and WebSocket
//! - Onion routing with 2-3 configurable hops
//! - FEC (Forward Error Correction) with Tetrys
//! - Mesh networking and peer discovery
//! - Cryptographic primitives with Perfect Forward Secrecy

pub mod error;
pub mod peer;
pub mod transport;
pub mod onion;
pub mod fec;
pub mod mesh;
pub mod crypto;
pub mod config;
pub mod traffic_cache;
pub mod multipath_distribution;
pub mod mesh_integration;
pub mod anonymity_layer;
pub mod performance_optimizer;
pub mod quantum_crypto;
pub mod adaptive_onion_router;
pub mod autonomous_health_monitor;
pub mod intelligent_circuit_redundancy;

pub use error::*;
pub use peer::*;
pub use transport::*;
pub use onion::*;
pub use fec::*;
pub use mesh::*;
pub use crypto::*;
pub use config::*;
pub use traffic_cache::*;
pub use multipath_distribution::*;
pub use mesh_integration::*;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "zMesh";

/// Maximum supported hops in onion routing
pub const MAX_HOPS: u8 = 3;
pub const MIN_HOPS: u8 = 2;

/// Default configuration values
pub const DEFAULT_HOPS: u8 = 2;
pub const DEFAULT_FEC_ENABLED: bool = true;
pub const DEFAULT_EXIT_TYPE: ExitType = ExitType::Direct;

/// Chunk size for data transmission (optimized for WebRTC)
pub const CHUNK_SIZE: usize = 16384; // 16KB

/// Maximum message size before chunking
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB