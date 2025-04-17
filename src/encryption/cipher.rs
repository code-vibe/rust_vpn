//! Encryption and decryption functionality
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, AeadInPlace,
    aead::{Aead, Nonce, Payload},
};
use rand::{rngs::OsRng, RngCore};
use blake2::{Blake2b512, Digest};
use std::error::Error;
use std::fmt;

/// Length of the nonce in bytes
const NONCE_LEN: usize = 12;

/// Errors related to cipher operations
#[derive(Debug)]
pub enum CipherError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonce,
    InvalidData,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherError::EncryptionFailed => write!(f, "Encryption failed"),
            CipherError::DecryptionFailed => write!(f, "Decryption failed"),
            CipherError::InvalidNonce => write!(f, "Invalid nonce"),
            CipherError::InvalidData => write!(f, "Invalid data"),
        }
    }
}

impl Error for CipherError {}

/// Cipher suite for VPN encryption/decryption
pub struct CipherSuite {
    cipher: ChaCha20Poly1305,
}

impl CipherSuite {
    /// Create a new cipher suite from a shared secret
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        // Derive a key from the shared secret using Blake2b
        let mut hasher = Blake2b512::new();
        hasher.update(shared_secret);
        let hash = hasher.finalize();

        // Use the first 32 bytes of the hash as the key
        let key = &hash[0..32];
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .expect("Key should be valid");

        CipherSuite { cipher }
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CipherError::EncryptionFailed)?;

        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Ensure the data is long enough to contain a nonce
        if encrypted_data.len() <= NONCE_LEN {
            return Err(CipherError::InvalidData);
        }

        // Split the data into nonce and ciphertext
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&encrypted_data[0..NONCE_LEN]);
        let ciphertext = &encrypted_data[NONCE_LEN..];

        // Decrypt the data
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CipherError::DecryptionFailed)
    }

    /// Encrypt data in place with associated data
    pub fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<(), CipherError> {
        if nonce.len() != NONCE_LEN {
            return Err(CipherError::InvalidNonce);
        }

        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(nonce);

        self.cipher
            .encrypt_in_place_detached(nonce, aad, buffer)
            .map_err(|_| CipherError::EncryptionFailed)?;

        Ok(())
    }

    /// Decrypt data in place with associated data
    pub fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<(), CipherError> {
        if nonce.len() != NONCE_LEN {
            return Err(CipherError::InvalidNonce);
        }

        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(nonce);

        self.cipher
            .decrypt_in_place_detached(nonce, aad, buffer, &[0u8; 16]) // Fix this - need actual tag
            .map_err(|_| CipherError::DecryptionFailed)?;

        Ok(())
    }
}