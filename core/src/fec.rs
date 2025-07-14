//! Forward Error Correction (FEC) using Tetrys (RFC 9407)
//!
//! Tetrys is a sliding-window FEC scheme that provides:
//! - Rateless coding (adaptive repair rate)
//! - Low CPU overhead
//! - Real-time loss recovery
//! - Adaptive epsilon (ε) based on loss estimation

use crate::{zMeshError, zMeshResult};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Default sliding window size
pub const DEFAULT_WINDOW_SIZE: usize = 64;

/// Default repair rate (epsilon)
pub const DEFAULT_EPSILON: f64 = 0.1; // 10% repair symbols

/// Maximum epsilon value
pub const MAX_EPSILON: f64 = 0.5; // 50% repair symbols

/// Minimum epsilon value
pub const MIN_EPSILON: f64 = 0.01; // 1% repair symbols

/// Symbol size for FEC encoding
pub const SYMBOL_SIZE: usize = 1024; // 1KB symbols

/// FEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecConfig {
    /// Enable FEC
    pub enabled: bool,
    /// Sliding window size
    pub window_size: usize,
    /// Initial repair rate (epsilon)
    pub initial_epsilon: f64,
    /// Adaptive epsilon adjustment
    pub adaptive_epsilon: bool,
    /// Loss estimation window
    pub loss_window: usize,
    /// Symbol size in bytes
    pub symbol_size: usize,
    /// Maximum repair symbols per window
    pub max_repair_symbols: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_size: DEFAULT_WINDOW_SIZE,
            initial_epsilon: DEFAULT_EPSILON,
            adaptive_epsilon: true,
            loss_window: 100, // Track loss over 100 packets
            symbol_size: SYMBOL_SIZE,
            max_repair_symbols: 32, // Max 32 repair symbols per window
        }
    }
}

impl FecConfig {
    /// Validate FEC configuration
    pub fn validate(&self) -> zMeshResult<()> {
        if self.initial_epsilon < MIN_EPSILON || self.initial_epsilon > MAX_EPSILON {
            return Err(zMeshError::Fec(format!(
                "Invalid epsilon: {} (must be between {} and {})",
                self.initial_epsilon, MIN_EPSILON, MAX_EPSILON
            )));
        }
        
        if self.window_size == 0 || self.window_size > 1024 {
            return Err(zMeshError::Fec(
                "Window size must be between 1 and 1024".to_string()
            ));
        }
        
        if self.symbol_size == 0 || self.symbol_size > 65536 {
            return Err(zMeshError::Fec(
                "Symbol size must be between 1 and 65536 bytes".to_string()
            ));
        }
        
        Ok(())
    }
}

/// FEC symbol identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId {
    /// Source block number
    pub block: u32,
    /// Symbol index within block
    pub index: u16,
}

impl SymbolId {
    /// Create new symbol ID
    pub fn new(block: u32, index: u16) -> Self {
        Self { block, index }
    }
}

/// FEC symbol types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolType {
    /// Source symbol (original data)
    Source,
    /// Repair symbol (redundancy)
    Repair,
}

/// FEC encoded symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecSymbol {
    /// Symbol identifier
    pub id: SymbolId,
    /// Symbol type
    pub symbol_type: SymbolType,
    /// Encoded data
    pub data: Bytes,
    /// Encoding vector (for repair symbols)
    pub encoding_vector: Option<Vec<u8>>,
}

impl FecSymbol {
    /// Create source symbol
    pub fn source(id: SymbolId, data: Bytes) -> Self {
        Self {
            id,
            symbol_type: SymbolType::Source,
            data,
            encoding_vector: None,
        }
    }
    
    /// Create repair symbol
    pub fn repair(id: SymbolId, data: Bytes, encoding_vector: Vec<u8>) -> Self {
        Self {
            id,
            symbol_type: SymbolType::Repair,
            data,
            encoding_vector: Some(encoding_vector),
        }
    }
    
    /// Check if symbol is source
    pub fn is_source(&self) -> bool {
        matches!(self.symbol_type, SymbolType::Source)
    }
    
    /// Check if symbol is repair
    pub fn is_repair(&self) -> bool {
        matches!(self.symbol_type, SymbolType::Repair)
    }
}

/// Loss estimation using Exponential Moving Average (EMA)
#[derive(Debug, Clone)]
pub struct LossEstimator {
    /// EMA of loss rate
    loss_rate: f64,
    /// Smoothing factor (alpha)
    alpha: f64,
    /// Recent packet history
    history: VecDeque<bool>, // true = received, false = lost
    /// Maximum history size
    max_history: usize,
}

impl LossEstimator {
    /// Create new loss estimator
    pub fn new(alpha: f64, max_history: usize) -> Self {
        Self {
            loss_rate: 0.0,
            alpha,
            history: VecDeque::new(),
            max_history,
        }
    }
    
    /// Update with packet reception status
    pub fn update(&mut self, received: bool) {
        // Add to history
        self.history.push_back(received);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
        
        // Calculate current window loss rate
        let lost_count = self.history.iter().filter(|&&r| !r).count();
        let window_loss_rate = lost_count as f64 / self.history.len() as f64;
        
        // Update EMA
        self.loss_rate = self.alpha * window_loss_rate + (1.0 - self.alpha) * self.loss_rate;
    }
    
    /// Get current loss rate estimate
    pub fn loss_rate(&self) -> f64 {
        self.loss_rate
    }
    
    /// Calculate adaptive epsilon based on loss rate
    pub fn adaptive_epsilon(&self, base_epsilon: f64) -> f64 {
        // Increase epsilon when loss rate is high
        let adaptive_factor = 1.0 + (self.loss_rate * 2.0); // Up to 3x base epsilon
        let epsilon = base_epsilon * adaptive_factor;
        epsilon.min(MAX_EPSILON).max(MIN_EPSILON)
    }
}

/// Sliding window for FEC encoding/decoding
#[derive(Debug)]
pub struct SlidingWindow {
    /// Window size
    size: usize,
    /// Current window symbols
    symbols: HashMap<SymbolId, FecSymbol>,
    /// Window start block
    start_block: u32,
    /// Next symbol index
    next_index: u16,
}

impl SlidingWindow {
    /// Create new sliding window
    pub fn new(size: usize) -> Self {
        Self {
            size,
            symbols: HashMap::new(),
            start_block: 0,
            next_index: 0,
        }
    }
    
    /// Add symbol to window
    pub fn add_symbol(&mut self, symbol: FecSymbol) -> zMeshResult<()> {
        // Check if symbol belongs to current window
        if !self.is_in_window(symbol.id) {
            return Err(zMeshError::Fec("Symbol outside window".to_string()));
        }
        
        self.symbols.insert(symbol.id, symbol);
        
        // Slide window if needed
        if self.symbols.len() > self.size {
            self.slide_window();
        }
        
        Ok(())
    }
    
    /// Get symbol by ID
    pub fn get_symbol(&self, id: SymbolId) -> Option<&FecSymbol> {
        self.symbols.get(&id)
    }
    
    /// Check if symbol ID is in current window
    pub fn is_in_window(&self, id: SymbolId) -> bool {
        id.block >= self.start_block && 
        id.block < self.start_block + (self.size as u32 / 64) // Assume 64 symbols per block
    }
    
    /// Slide window forward
    fn slide_window(&mut self) {
        // Remove oldest symbols
        let cutoff_block = self.start_block;
        self.symbols.retain(|id, _| id.block > cutoff_block);
        self.start_block += 1;
    }
    
    /// Get missing source symbols in window
    pub fn missing_source_symbols(&self) -> Vec<SymbolId> {
        let mut missing = Vec::new();
        
        // Check for gaps in source symbols
        for block in self.start_block..self.start_block + (self.size as u32 / 64) {
            for index in 0..64 {
                let id = SymbolId::new(block, index);
                if !self.symbols.contains_key(&id) {
                    missing.push(id);
                }
            }
        }
        
        missing
    }
    
    /// Get available repair symbols
    pub fn repair_symbols(&self) -> Vec<&FecSymbol> {
        self.symbols.values().filter(|s| s.is_repair()).collect()
    }
}

/// Tetrys FEC encoder
pub struct TetrysEncoder {
    config: FecConfig,
    window: SlidingWindow,
    loss_estimator: LossEstimator,
    current_epsilon: f64,
}

impl TetrysEncoder {
    /// Create new Tetrys encoder
    pub fn new(config: FecConfig) -> zMeshResult<Self> {
        config.validate()?;
        
        let window = SlidingWindow::new(config.window_size);
        let loss_estimator = LossEstimator::new(0.1, config.loss_window); // alpha = 0.1
        
        Ok(Self {
            current_epsilon: config.initial_epsilon,
            config,
            window,
            loss_estimator,
        })
    }
    
    /// Encode data into FEC symbols
    pub fn encode(&mut self, data: &[u8]) -> zMeshResult<Vec<FecSymbol>> {
        if !self.config.enabled {
            // If FEC disabled, just return source symbols
            return self.encode_source_only(data);
        }
        
        let mut symbols = Vec::new();
        
        // Split data into symbols
        let chunks: Vec<&[u8]> = data.chunks(self.config.symbol_size).collect();
        
        // Create source symbols
        for (i, chunk) in chunks.iter().enumerate() {
            let id = SymbolId::new(0, i as u16); // Simplified block numbering
            let symbol = FecSymbol::source(id, Bytes::copy_from_slice(chunk));
            symbols.push(symbol);
        }
        
        // Generate repair symbols based on current epsilon
        let repair_count = (chunks.len() as f64 * self.current_epsilon).ceil() as usize;
        let repair_count = repair_count.min(self.config.max_repair_symbols);
        
        for i in 0..repair_count {
            let repair_symbol = self.generate_repair_symbol(i, &chunks)?;
            symbols.push(repair_symbol);
        }
        
        Ok(symbols)
    }
    
    /// Update loss estimation and adapt epsilon
    pub fn update_loss_stats(&mut self, received: bool) {
        self.loss_estimator.update(received);
        
        if self.config.adaptive_epsilon {
            self.current_epsilon = self.loss_estimator.adaptive_epsilon(self.config.initial_epsilon);
        }
    }
    
    /// Get current epsilon value
    pub fn current_epsilon(&self) -> f64 {
        self.current_epsilon
    }
    
    /// Get current loss rate estimate
    pub fn loss_rate(&self) -> f64 {
        self.loss_estimator.loss_rate()
    }
    
    /// Encode source symbols only (FEC disabled)
    fn encode_source_only(&self, data: &[u8]) -> zMeshResult<Vec<FecSymbol>> {
        let mut symbols = Vec::new();
        
        for (i, chunk) in data.chunks(self.config.symbol_size).enumerate() {
            let id = SymbolId::new(0, i as u16);
            let symbol = FecSymbol::source(id, Bytes::copy_from_slice(chunk));
            symbols.push(symbol);
        }
        
        Ok(symbols)
    }
    
    /// Generate repair symbol using linear combination
    fn generate_repair_symbol(&self, repair_index: usize, chunks: &[&[u8]]) -> zMeshResult<FecSymbol> {
        // Simplified repair symbol generation
        // In a real implementation, this would use proper Reed-Solomon or similar
        
        let mut repair_data = vec![0u8; self.config.symbol_size];
        let mut encoding_vector = vec![0u8; chunks.len()];
        
        // Generate pseudo-random encoding vector
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(repair_index as u64);
        
        for i in 0..chunks.len() {
            encoding_vector[i] = rng.gen_range(1..=255); // Non-zero coefficients
        }
        
        // Compute linear combination
        for (i, chunk) in chunks.iter().enumerate() {
            let coeff = encoding_vector[i];
            for (j, &byte) in chunk.iter().enumerate() {
                if j < repair_data.len() {
                    repair_data[j] ^= galois_multiply(byte, coeff);
                }
            }
        }
        
        let id = SymbolId::new(0, (chunks.len() + repair_index) as u16);
        Ok(FecSymbol::repair(id, Bytes::from(repair_data), encoding_vector))
    }
}

/// Tetrys FEC decoder
pub struct TetrysDecoder {
    config: FecConfig,
    window: SlidingWindow,
}

impl TetrysDecoder {
    /// Create new Tetrys decoder
    pub fn new(config: FecConfig) -> zMeshResult<Self> {
        config.validate()?;
        
        let window = SlidingWindow::new(config.window_size);
        
        Ok(Self {
            config,
            window,
        })
    }
    
    /// Add received symbol
    pub fn add_symbol(&mut self, symbol: FecSymbol) -> zMeshResult<()> {
        self.window.add_symbol(symbol)
    }
    
    /// Attempt to decode missing symbols
    pub fn decode(&mut self) -> zMeshResult<Vec<Bytes>> {
        if !self.config.enabled {
            // If FEC disabled, just return available source symbols
            return self.decode_source_only();
        }
        
        // TODO: Implement actual decoding using Gaussian elimination
        // For now, return available source symbols
        self.decode_source_only()
    }
    
    /// Decode source symbols only
    fn decode_source_only(&self) -> zMeshResult<Vec<Bytes>> {
        let mut data = Vec::new();
        
        // Collect source symbols in order
        let mut source_symbols: Vec<_> = self.window.symbols.values()
            .filter(|s| s.is_source())
            .collect();
        
        source_symbols.sort_by_key(|s| (s.id.block, s.id.index));
        
        for symbol in source_symbols {
            data.push(symbol.data.clone());
        }
        
        Ok(data)
    }
}

/// Galois field multiplication (GF(256))
fn galois_multiply(a: u8, b: u8) -> u8 {
    // Simplified GF(256) multiplication
    // In a real implementation, use lookup tables for performance
    if a == 0 || b == 0 {
        return 0;
    }
    
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a = if a & 0x80 != 0 {
            (a << 1) ^ 0x1d // Primitive polynomial
        } else {
            a << 1
        };
        b >>= 1;
    }
    
    result
}