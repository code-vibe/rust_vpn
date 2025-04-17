//! Key management functionality
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use std::fmt;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Errors related to key operations
#[derive(Debug)]
pub enum KeyError {
    InvalidKeyFormat,
    IoError(std::io::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::InvalidKeyFormat => write!(f, "Invalid key format"),
            KeyError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl Error for KeyError {}

impl From<std::io::Error> for KeyError {
    fn from(err: std::io::Error) -> Self {
        KeyError::IoError(err)
    }
}

/// Key pair for VPN encryption
pub struct KeyPair {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let private_key = StaticSecret::new(&OsRng);
        let public_key = PublicKey::from(&private_key);

        KeyPair {
            private_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Compute a shared secret with another public key
    pub fn shared_secret(&self, peer_public: &PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(peer_public);
        shared_secret.to_bytes()
    }

    /// Save the key pair to files
    pub fn save_to_files(&self, private_path: &Path, public_path: &Path) -> Result<(), KeyError> {
        let mut private_file = File::create(private_path)?;
        private_file.write_all(&self.private_key.to_bytes())?;

        let mut public_file = File::create(public_path)?;
        public_file.write_all(self.public_key.as_bytes())?;

        Ok(())
    }

    /// Load a key pair from files
    pub fn load_from_files(private_path: &Path, public_path: &Path) -> Result<Self, KeyError> {
        let mut private_bytes = [0u8; 32];
        let mut private_file = File::open(private_path)?;
        private_file.read_exact(&mut private_bytes)?;

        let mut public_bytes = [0u8; 32];
        let mut public_file = File::open(public_path)?;
        public_file.read_exact(&mut public_bytes)?;

        let private_key = StaticSecret::from(private_bytes);
        let public_key = PublicKey::from(public_bytes);

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }
}