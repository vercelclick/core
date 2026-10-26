use serde::{Deserialize, Serialize};

// No keys for smaller payloads
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPackage(
    /** ECC public key bytes */ pub Option<Vec<u8>>,
    /** KEM public key bytes */ pub Option<Vec<u8>>,
    /** Nonce Bytes */ pub [u8; 12],
    /** Encrypted payload */ pub Vec<u8>,
);

impl EncryptedPackage {
    pub fn ecc_public_key(&self) -> [u8; 32] {
        let key_bytes: [u8; 32] = self.0.clone().unwrap().as_slice().try_into().unwrap();
        key_bytes
    }

    pub fn kem_ciphertext(&self) -> [u8; 1088] {
        let key_bytes: [u8; 1088] = self.1.clone().unwrap().as_slice().try_into().unwrap();
        key_bytes
    }
}
