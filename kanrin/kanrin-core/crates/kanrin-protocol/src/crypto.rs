use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
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

/// Derive a 96-bit AEAD nonce deterministically from a chunk's sequence number.
///
/// The nonce is `[0u8; 4] || seq.to_be_bytes()`. Because each direction encrypts
/// under a distinct key (`client_write_key` vs `server_write_key`) and the
/// sequence is strictly increasing and unique per direction, no `(key, nonce)`
/// pair is ever reused.
///
/// Carrying the sequence on the wire and deriving the nonce from it — rather
/// than from a positional counter that assumes in-order, gap-free delivery —
/// is what lets the receiver decrypt chunks that arrive reordered, replayed onto
/// a new transport, or striped across multiple paths.
pub fn nonce_from_sequence(seq: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[NONCE_SIZE - 8..].copy_from_slice(&seq.to_be_bytes());
    nonce
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

/// Derive the key used to prove session ownership when resuming on a new
/// transport (16.1.6).
///
/// Deliberately a *separate* key rather than one of the AEAD write keys: the
/// resumption proof is computed over attacker-visible material, so reusing an
/// encryption key for it would mix two primitives under one key. The distinct
/// HKDF `info` string keeps the domains apart.
///
/// Both write keys feed the input, so the value is identical on client and
/// server and cannot be derived by anyone who did not complete the handshake.
pub fn derive_resumption_key(keys: &SessionKeys) -> Result<[u8; KEY_SIZE], ProtocolError> {
    let mut ikm = [0u8; KEY_SIZE * 2];
    ikm[..KEY_SIZE].copy_from_slice(&keys.client_write_key);
    ikm[KEY_SIZE..].copy_from_slice(&keys.server_write_key);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; KEY_SIZE];
    hk.expand(b"kanrin-resumption", &mut key)
        .map_err(|e| ProtocolError::Crypto(format!("HKDF expand failed: {}", e)))?;

    ikm.zeroize();
    Ok(key)
}

/// HMAC-SHA256 over the concatenated `parts`.
///
/// Callers must keep the transcript unambiguous — every field fed in is
/// fixed-width, so plain concatenation cannot be re-split into a different
/// message.
pub fn mac_sha256(key: &[u8; KEY_SIZE], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
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
