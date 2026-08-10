use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ProtocolError;

/// AEAD tag size for ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16;

/// Key size for ChaCha20-Poly1305
pub const KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20-Poly1305
pub const NONCE_SIZE: usize = 12;

/// Maximum nonce value before key rotation is required
pub const MAX_NONCE: u64 = u64::MAX - 1;

/// Session keys derived from the handshake shared secret.
/// Both sides derive identical keys deterministically.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub client_write_key: [u8; KEY_SIZE],
    pub server_write_key: [u8; KEY_SIZE],
}

/// Tracks nonce state for a single direction (send or receive).
#[derive(Debug, Clone)]
pub struct NonceCounter {
    value: u64,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Increment and return the next nonce. Errors if exhausted.
    pub fn next(&mut self) -> Result<[u8; NONCE_SIZE], ProtocolError> {
        if self.value >= MAX_NONCE {
            return Err(ProtocolError::NonceExhausted);
        }
        let nonce_bytes = self.to_bytes();
        self.value += 1;
        Ok(nonce_bytes)
    }

    /// Current nonce as bytes (little-endian, zero-padded to 12 bytes).
    fn to_bytes(&self) -> [u8; NONCE_SIZE] {
        let mut buf = [0u8; NONCE_SIZE];
        buf[..8].copy_from_slice(&self.value.to_le_bytes());
        buf
    }

    pub fn current(&self) -> u64 {
        self.value
    }
}

/// Derive session keys from a shared secret using HKDF-SHA256.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    salt: &[u8],
) -> Result<SessionKeys, ProtocolError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut client_key = [0u8; KEY_SIZE];
    let mut server_key = [0u8; KEY_SIZE];

    hk.expand(b"kanrin-client-write", &mut client_key)
        .map_err(|e| ProtocolError::Crypto(format!("HKDF expand failed: {}", e)))?;

    hk.expand(b"kanrin-server-write", &mut server_key)
        .map_err(|e| ProtocolError::Crypto(format!("HKDF expand failed: {}", e)))?;

    Ok(SessionKeys {
        client_write_key: client_key,
        server_write_key: server_key,
    })
}

/// Encrypt plaintext with ChaCha20-Poly1305.
/// Returns ciphertext (plaintext.len() + TAG_SIZE bytes).
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ProtocolError::Crypto(format!("cipher init: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| ProtocolError::Crypto(format!("encrypt: {}", e)))
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
/// Returns plaintext or error if authentication fails.
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ProtocolError::Crypto(format!("cipher init: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| ProtocolError::Crypto("decryption failed (authentication)".into()))
}

/// Constant-time comparison of two byte slices.
/// Prevents timing side-channel attacks on auth tokens.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    buf
}

/// Generate random bytes into a Vec of specified length.
pub fn random_bytes_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    buf
}

/// X25519 key pair for ephemeral key exchange.
pub struct KeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform X25519 Diffie-Hellman key exchange.
    /// Consumes self (ephemeral secret is single-use).
    pub fn diffie_hellman(self, peer_public: &PublicKey) -> [u8; 32] {
        let shared = self.secret.diffie_hellman(peer_public);
        *shared.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = random_bytes::<KEY_SIZE>();
        let nonce = random_bytes::<NONCE_SIZE>();
        let plaintext = b"hello kanrin protocol";
        let aad = b"additional data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = random_bytes::<KEY_SIZE>();
        let nonce = random_bytes::<NONCE_SIZE>();
        let plaintext = b"sensitive data";
        let aad = b"";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = random_bytes::<KEY_SIZE>();
        let nonce = random_bytes::<NONCE_SIZE>();
        let plaintext = b"data";

        let ciphertext = encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_counter_increments() {
        let mut counter = NonceCounter::new();
        let n1 = counter.next().unwrap();
        let n2 = counter.next().unwrap();
        assert_ne!(n1, n2);
        assert_eq!(counter.current(), 2);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let secret = random_bytes::<32>();
        let salt = random_bytes::<16>();

        let keys1 = derive_session_keys(&secret, &salt).unwrap();
        let keys2 = derive_session_keys(&secret, &salt).unwrap();

        assert_eq!(keys1.client_write_key, keys2.client_write_key);
        assert_eq!(keys1.server_write_key, keys2.server_write_key);
    }

    #[test]
    fn test_key_exchange_produces_shared_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_pub = *alice.public_key();
        let bob_pub = *bob.public_key();

        let alice_shared = alice.diffie_hellman(&bob_pub);
        let bob_shared = bob.diffie_hellman(&alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }
}
