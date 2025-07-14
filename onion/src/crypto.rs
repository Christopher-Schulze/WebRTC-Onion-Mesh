//! Cryptographic implementations for onion routing
//! Provides Perfect Forward Secrecy for all onion hops

use crate::error::{CryptoError, OnionResult};
use crnet_core::crypto::{CipherSuite, KeyExchange, KeyType};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported cipher suites for onion routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OnionCipherSuite {
    /// AES-256-GCM with HKDF-SHA256
    Aes256Gcm,
    /// ChaCha20-Poly1305 with HKDF-SHA256
    ChaCha20Poly1305,
}

impl Default for OnionCipherSuite {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

impl From<OnionCipherSuite> for CipherSuite {
    fn from(suite: OnionCipherSuite) -> Self {
        match suite {
            OnionCipherSuite::Aes256Gcm => CipherSuite::Aes256Gcm,
            OnionCipherSuite::ChaCha20Poly1305 => CipherSuite::ChaCha20Poly1305,
        }
    }
}

/// Supported key exchange methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OnionKeyExchange {
    /// X25519 Elliptic Curve Diffie-Hellman
    X25519,
    /// NIST P-256 Elliptic Curve Diffie-Hellman
    P256,
}

impl Default for OnionKeyExchange {
    fn default() -> Self {
        Self::X25519
    }
}

impl From<OnionKeyExchange> for KeyExchange {
    fn from(kx: OnionKeyExchange) -> Self {
        match kx {
            OnionKeyExchange::X25519 => KeyExchange::X25519,
            OnionKeyExchange::P256 => KeyExchange::P256,
        }
    }
}

/// Cryptographic key material with automatic zeroization
#[derive(Clone, ZeroizeOnDrop)]
pub struct OnionKey {
    /// Key material
    #[zeroize(skip)]
    pub key_type: KeyType,
    /// Raw key bytes
    pub material: Vec<u8>,
    /// Key creation timestamp
    #[zeroize(skip)]
    pub created_at: SystemTime,
    /// Key expiration time
    #[zeroize(skip)]
    pub expires_at: Option<SystemTime>,
}

impl OnionKey {
    /// Create a new onion key
    pub fn new(key_type: KeyType, material: Vec<u8>, lifetime: Option<Duration>) -> Self {
        let created_at = SystemTime::now();
        let expires_at = lifetime.map(|duration| created_at + duration);
        
        Self {
            key_type,
            material,
            created_at,
            expires_at,
        }
    }
    
    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }
    
    /// Get key age
    pub fn age(&self) -> Duration {
        SystemTime::now().duration_since(self.created_at).unwrap_or_default()
    }
    
    /// Get remaining lifetime
    pub fn remaining_lifetime(&self) -> Option<Duration> {
        self.expires_at.and_then(|expires_at| {
            expires_at.checked_duration_since(SystemTime::now()).ok()
        })
    }
}

impl std::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionKey")
            .field("key_type", &self.key_type)
            .field("material_len", &self.material.len())
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("is_expired", &self.is_expired())
            .finish()
    }
}

/// Encrypted data with authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionEncryptedData {
    /// Cipher suite used
    pub cipher_suite: OnionCipherSuite,
    /// Initialization vector/nonce
    pub nonce: Vec<u8>,
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
    /// Additional authenticated data (optional)
    pub aad: Option<Vec<u8>>,
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionKdfParams {
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Info parameter for HKDF
    pub info: Vec<u8>,
    /// Output key length
    pub length: usize,
}

/// Perfect Forward Secrecy key set for a single hop
#[derive(Debug, Clone)]
pub struct HopKeys {
    /// Forward encryption key (client -> relay)
    pub forward_key: OnionKey,
    /// Backward encryption key (relay -> client)
    pub backward_key: OnionKey,
    /// Forward MAC key
    pub forward_mac_key: OnionKey,
    /// Backward MAC key
    pub backward_mac_key: OnionKey,
    /// Key derivation parameters
    pub kdf_params: OnionKdfParams,
    /// Hop index in the circuit
    pub hop_index: u8,
}

impl HopKeys {
    /// Check if any key has expired
    pub fn is_expired(&self) -> bool {
        self.forward_key.is_expired() ||
        self.backward_key.is_expired() ||
        self.forward_mac_key.is_expired() ||
        self.backward_mac_key.is_expired()
    }
    
    /// Get the oldest key age
    pub fn oldest_key_age(&self) -> Duration {
        [&self.forward_key, &self.backward_key, &self.forward_mac_key, &self.backward_mac_key]
            .iter()
            .map(|key| key.age())
            .max()
            .unwrap_or_default()
    }
}

/// Circuit keys with Perfect Forward Secrecy
#[derive(Debug)]
pub struct CircuitKeys {
    /// Circuit identifier
    pub circuit_id: String,
    /// Keys for each hop (indexed by hop number)
    pub hop_keys: HashMap<u8, HopKeys>,
    /// Circuit creation timestamp
    pub created_at: SystemTime,
    /// Key rotation interval
    pub rotation_interval: Duration,
    /// Last key rotation timestamp
    pub last_rotation: SystemTime,
}

impl CircuitKeys {
    /// Create new circuit keys
    pub fn new(circuit_id: String, rotation_interval: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            circuit_id,
            hop_keys: HashMap::new(),
            created_at: now,
            rotation_interval,
            last_rotation: now,
        }
    }
    
    /// Add keys for a hop
    pub fn add_hop_keys(&mut self, hop_index: u8, keys: HopKeys) {
        self.hop_keys.insert(hop_index, keys);
    }
    
    /// Get keys for a specific hop
    pub fn get_hop_keys(&self, hop_index: u8) -> Option<&HopKeys> {
        self.hop_keys.get(&hop_index)
    }
    
    /// Check if keys need rotation
    pub fn needs_rotation(&self) -> bool {
        let time_since_rotation = SystemTime::now()
            .duration_since(self.last_rotation)
            .unwrap_or_default();
        
        time_since_rotation >= self.rotation_interval ||
        self.hop_keys.values().any(|keys| keys.is_expired())
    }
    
    /// Get circuit age
    pub fn age(&self) -> Duration {
        SystemTime::now().duration_since(self.created_at).unwrap_or_default()
    }
    
    /// Get number of hops
    pub fn hop_count(&self) -> usize {
        self.hop_keys.len()
    }
}

/// Onion cryptographic provider
pub struct OnionCrypto {
    /// Default cipher suite
    cipher_suite: OnionCipherSuite,
    /// Default key exchange method
    key_exchange: OnionKeyExchange,
    /// Key lifetime for PFS
    key_lifetime: Duration,
    /// Random number generator
    rng: Box<dyn CryptoRng + RngCore + Send + Sync>,
}

impl OnionCrypto {
    /// Create a new onion crypto provider
    pub fn new(
        cipher_suite: OnionCipherSuite,
        key_exchange: OnionKeyExchange,
        key_lifetime: Duration,
    ) -> Self {
        Self {
            cipher_suite,
            key_exchange,
            key_lifetime,
            rng: Box::new(rand::thread_rng()),
        }
    }
    
    /// Generate a new ephemeral key pair
    pub fn generate_ephemeral_keypair(&mut self) -> OnionResult<(OnionKey, OnionKey)> {
        match self.key_exchange {
            OnionKeyExchange::X25519 => self.generate_x25519_keypair(),
            OnionKeyExchange::P256 => self.generate_p256_keypair(),
        }
    }
    
    /// Generate X25519 key pair
    fn generate_x25519_keypair(&mut self) -> OnionResult<(OnionKey, OnionKey)> {
        use x25519_dalek::{EphemeralSecret, PublicKey};
        
        let secret = EphemeralSecret::random_from_rng(&mut self.rng);
        let public = PublicKey::from(&secret);
        
        let private_key = OnionKey::new(
            KeyType::Private,
            secret.to_bytes().to_vec(),
            Some(self.key_lifetime),
        );
        
        let public_key = OnionKey::new(
            KeyType::Public,
            public.as_bytes().to_vec(),
            Some(self.key_lifetime),
        );
        
        Ok((private_key, public_key))
    }
    
    /// Generate P256 key pair
    fn generate_p256_keypair(&mut self) -> OnionResult<(OnionKey, OnionKey)> {
        // Placeholder implementation - would use p256 crate in real implementation
        let mut private_bytes = vec![0u8; 32];
        self.rng.fill_bytes(&mut private_bytes);
        
        let mut public_bytes = vec![0u8; 33]; // Compressed point
        self.rng.fill_bytes(&mut public_bytes);
        public_bytes[0] = 0x02; // Compressed point prefix
        
        let private_key = OnionKey::new(
            KeyType::Private,
            private_bytes,
            Some(self.key_lifetime),
        );
        
        let public_key = OnionKey::new(
            KeyType::Public,
            public_bytes,
            Some(self.key_lifetime),
        );
        
        Ok((private_key, public_key))
    }
    
    /// Perform key exchange
    pub fn key_exchange(
        &self,
        private_key: &OnionKey,
        public_key: &OnionKey,
    ) -> OnionResult<OnionKey> {
        match self.key_exchange {
            OnionKeyExchange::X25519 => self.x25519_key_exchange(private_key, public_key),
            OnionKeyExchange::P256 => self.p256_key_exchange(private_key, public_key),
        }
    }
    
    /// X25519 key exchange
    fn x25519_key_exchange(
        &self,
        private_key: &OnionKey,
        public_key: &OnionKey,
    ) -> OnionResult<OnionKey> {
        use x25519_dalek::{EphemeralSecret, PublicKey};
        
        if private_key.material.len() != 32 || public_key.material.len() != 32 {
            return Err(CryptoError::InvalidKey("Invalid key size for X25519".to_string()).into());
        }
        
        let secret_bytes: [u8; 32] = private_key.material.as_slice().try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid private key format".to_string()))?;
        
        let public_bytes: [u8; 32] = public_key.material.as_slice().try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid public key format".to_string()))?;
        
        let secret = EphemeralSecret::from(secret_bytes);
        let public = PublicKey::from(public_bytes);
        
        let shared_secret = secret.diffie_hellman(&public);
        
        Ok(OnionKey::new(
            KeyType::Shared,
            shared_secret.as_bytes().to_vec(),
            Some(self.key_lifetime),
        ))
    }
    
    /// P256 key exchange
    fn p256_key_exchange(
        &self,
        _private_key: &OnionKey,
        _public_key: &OnionKey,
    ) -> OnionResult<OnionKey> {
        // Placeholder implementation - would use p256 crate in real implementation
        Err(CryptoError::UnsupportedKeyExchange("P256 not implemented".to_string()).into())
    }
    
    /// Derive keys using HKDF
    pub fn derive_keys(
        &self,
        shared_secret: &OnionKey,
        params: &OnionKdfParams,
    ) -> OnionResult<Vec<OnionKey>> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let hkdf = Hkdf::<Sha256>::new(Some(&params.salt), &shared_secret.material);
        
        // Derive 4 keys: forward_enc, backward_enc, forward_mac, backward_mac
        let mut keys = Vec::new();
        let key_size = match self.cipher_suite {
            OnionCipherSuite::Aes256Gcm => 32,
            OnionCipherSuite::ChaCha20Poly1305 => 32,
        };
        
        for i in 0..4 {
            let mut key_material = vec![0u8; key_size];
            let info = [&params.info, &[i]].concat();
            
            hkdf.expand(&info, &mut key_material)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            
            let key_type = match i {
                0 | 1 => KeyType::Encryption,
                2 | 3 => KeyType::Mac,
                _ => unreachable!(),
            };
            
            keys.push(OnionKey::new(
                key_type,
                key_material,
                Some(self.key_lifetime),
            ));
        }
        
        Ok(keys)
    }
    
    /// Generate hop keys for Perfect Forward Secrecy
    pub fn generate_hop_keys(
        &mut self,
        hop_index: u8,
        shared_secret: &OnionKey,
    ) -> OnionResult<HopKeys> {
        // Generate salt and info for KDF
        let mut salt = vec![0u8; 32];
        self.rng.fill_bytes(&mut salt);
        
        let info = format!("crnet-onion-hop-{}", hop_index).into_bytes();
        
        let kdf_params = OnionKdfParams {
            salt,
            info,
            length: 32,
        };
        
        // Derive the four keys
        let derived_keys = self.derive_keys(shared_secret, &kdf_params)?;
        
        if derived_keys.len() != 4 {
            return Err(CryptoError::KeyDerivationFailed(
                "Expected 4 derived keys".to_string()
            ).into());
        }
        
        Ok(HopKeys {
            forward_key: derived_keys[0].clone(),
            backward_key: derived_keys[1].clone(),
            forward_mac_key: derived_keys[2].clone(),
            backward_mac_key: derived_keys[3].clone(),
            kdf_params,
            hop_index,
        })
    }
    
    /// Encrypt data for onion routing
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        key: &OnionKey,
        aad: Option<&[u8]>,
    ) -> OnionResult<OnionEncryptedData> {
        match self.cipher_suite {
            OnionCipherSuite::Aes256Gcm => self.encrypt_aes_gcm(plaintext, key, aad),
            OnionCipherSuite::ChaCha20Poly1305 => self.encrypt_chacha20_poly1305(plaintext, key, aad),
        }
    }
    
    /// Decrypt data for onion routing
    pub fn decrypt(
        &self,
        encrypted_data: &OnionEncryptedData,
        key: &OnionKey,
    ) -> OnionResult<Vec<u8>> {
        match encrypted_data.cipher_suite {
            OnionCipherSuite::Aes256Gcm => self.decrypt_aes_gcm(encrypted_data, key),
            OnionCipherSuite::ChaCha20Poly1305 => self.decrypt_chacha20_poly1305(encrypted_data, key),
        }
    }
    
    /// Encrypt with AES-256-GCM
    fn encrypt_aes_gcm(
        &mut self,
        plaintext: &[u8],
        key: &OnionKey,
        aad: Option<&[u8]>,
    ) -> OnionResult<OnionEncryptedData> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, AeadInPlace};
        
        if key.material.len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 requires 32-byte key".to_string()).into());
        }
        
        let cipher = Aes256Gcm::new_from_slice(&key.material)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, aad.unwrap_or(&[]), &mut buffer)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        Ok(OnionEncryptedData {
            cipher_suite: OnionCipherSuite::Aes256Gcm,
            nonce: nonce_bytes.to_vec(),
            ciphertext: buffer,
            tag: tag.to_vec(),
            aad: aad.map(|a| a.to_vec()),
        })
    }
    
    /// Decrypt with AES-256-GCM
    fn decrypt_aes_gcm(
        &self,
        encrypted_data: &OnionEncryptedData,
        key: &OnionKey,
    ) -> OnionResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, AeadInPlace, Tag};
        
        if key.material.len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 requires 32-byte key".to_string()).into());
        }
        
        let cipher = Aes256Gcm::new_from_slice(&key.material)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let nonce = Nonce::from_slice(&encrypted_data.nonce);
        let tag = Tag::from_slice(&encrypted_data.tag);
        
        let mut buffer = encrypted_data.ciphertext.clone();
        cipher.decrypt_in_place_detached(
            nonce,
            encrypted_data.aad.as_deref().unwrap_or(&[]),
            &mut buffer,
            tag,
        ).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        Ok(buffer)
    }
    
    /// Encrypt with ChaCha20-Poly1305
    fn encrypt_chacha20_poly1305(
        &mut self,
        plaintext: &[u8],
        key: &OnionKey,
        aad: Option<&[u8]>,
    ) -> OnionResult<OnionEncryptedData> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, AeadInPlace};
        
        if key.material.len() != 32 {
            return Err(CryptoError::InvalidKey("ChaCha20 requires 32-byte key".to_string()).into());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key.material)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, aad.unwrap_or(&[]), &mut buffer)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        Ok(OnionEncryptedData {
            cipher_suite: OnionCipherSuite::ChaCha20Poly1305,
            nonce: nonce_bytes.to_vec(),
            ciphertext: buffer,
            tag: tag.to_vec(),
            aad: aad.map(|a| a.to_vec()),
        })
    }
    
    /// Decrypt with ChaCha20-Poly1305
    fn decrypt_chacha20_poly1305(
        &self,
        encrypted_data: &OnionEncryptedData,
        key: &OnionKey,
    ) -> OnionResult<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, AeadInPlace, Tag};
        
        if key.material.len() != 32 {
            return Err(CryptoError::InvalidKey("ChaCha20 requires 32-byte key".to_string()).into());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key.material)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let nonce = Nonce::from_slice(&encrypted_data.nonce);
        let tag = Tag::from_slice(&encrypted_data.tag);
        
        let mut buffer = encrypted_data.ciphertext.clone();
        cipher.decrypt_in_place_detached(
            nonce,
            encrypted_data.aad.as_deref().unwrap_or(&[]),
            &mut buffer,
            tag,
        ).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        Ok(buffer)
    }
    
    /// Generate random bytes
    pub fn random_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_onion_key_creation() {
        let key = OnionKey::new(
            KeyType::Encryption,
            vec![1, 2, 3, 4],
            Some(Duration::from_secs(3600)),
        );
        
        assert_eq!(key.key_type, KeyType::Encryption);
        assert_eq!(key.material, vec![1, 2, 3, 4]);
        assert!(!key.is_expired());
        assert!(key.age() < Duration::from_secs(1));
    }
    
    #[test]
    fn test_onion_crypto_creation() {
        let crypto = OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        );
        
        assert_eq!(crypto.cipher_suite, OnionCipherSuite::ChaCha20Poly1305);
        assert_eq!(crypto.key_exchange, OnionKeyExchange::X25519);
        assert_eq!(crypto.key_lifetime, Duration::from_secs(3600));
    }
    
    #[test]
    fn test_x25519_keypair_generation() {
        let mut crypto = OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        );
        
        let (private_key, public_key) = crypto.generate_ephemeral_keypair().unwrap();
        
        assert_eq!(private_key.key_type, KeyType::Private);
        assert_eq!(public_key.key_type, KeyType::Public);
        assert_eq!(private_key.material.len(), 32);
        assert_eq!(public_key.material.len(), 32);
    }
    
    #[test]
    fn test_key_exchange() {
        let mut crypto = OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        );
        
        let (alice_private, alice_public) = crypto.generate_ephemeral_keypair().unwrap();
        let (bob_private, bob_public) = crypto.generate_ephemeral_keypair().unwrap();
        
        let alice_shared = crypto.key_exchange(&alice_private, &bob_public).unwrap();
        let bob_shared = crypto.key_exchange(&bob_private, &alice_public).unwrap();
        
        assert_eq!(alice_shared.material, bob_shared.material);
        assert_eq!(alice_shared.key_type, KeyType::Shared);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let mut crypto = OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        );
        
        let key = OnionKey::new(
            KeyType::Encryption,
            crypto.random_bytes(32),
            Some(Duration::from_secs(3600)),
        );
        
        let plaintext = b"Hello, Onion Routing!";
        let aad = Some(b"additional data".as_slice());
        
        let encrypted = crypto.encrypt(plaintext, &key, aad).unwrap();
        let decrypted = crypto.decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_hop_keys_generation() {
        let mut crypto = OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        );
        
        let shared_secret = OnionKey::new(
            KeyType::Shared,
            crypto.random_bytes(32),
            Some(Duration::from_secs(3600)),
        );
        
        let hop_keys = crypto.generate_hop_keys(1, &shared_secret).unwrap();
        
        assert_eq!(hop_keys.hop_index, 1);
        assert_eq!(hop_keys.forward_key.key_type, KeyType::Encryption);
        assert_eq!(hop_keys.backward_key.key_type, KeyType::Encryption);
        assert_eq!(hop_keys.forward_mac_key.key_type, KeyType::Mac);
        assert_eq!(hop_keys.backward_mac_key.key_type, KeyType::Mac);
        assert!(!hop_keys.is_expired());
    }
    
    #[test]
    fn test_circuit_keys() {
        let mut circuit_keys = CircuitKeys::new(
            "test-circuit".to_string(),
            Duration::from_secs(1800),
        );
        
        assert_eq!(circuit_keys.circuit_id, "test-circuit");
        assert_eq!(circuit_keys.hop_count(), 0);
        assert!(!circuit_keys.needs_rotation());
        
        // Add some mock hop keys
        let hop_keys = HopKeys {
            forward_key: OnionKey::new(KeyType::Encryption, vec![1; 32], Some(Duration::from_secs(3600))),
            backward_key: OnionKey::new(KeyType::Encryption, vec![2; 32], Some(Duration::from_secs(3600))),
            forward_mac_key: OnionKey::new(KeyType::Mac, vec![3; 32], Some(Duration::from_secs(3600))),
            backward_mac_key: OnionKey::new(KeyType::Mac, vec![4; 32], Some(Duration::from_secs(3600))),
            kdf_params: OnionKdfParams {
                salt: vec![5; 32],
                info: b"test".to_vec(),
                length: 32,
            },
            hop_index: 1,
        };
        
        circuit_keys.add_hop_keys(1, hop_keys);
        assert_eq!(circuit_keys.hop_count(), 1);
        assert!(circuit_keys.get_hop_keys(1).is_some());
        assert!(circuit_keys.get_hop_keys(2).is_none());
    }
}