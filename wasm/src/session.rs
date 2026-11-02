use crate::passkeys::prf::PrfResults;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::{PrivateKey, PrivateKeySeed, PublicKey};

#[derive(Clone)]
pub struct SecureSession {
    private_key: PrivateKey,
}

impl SecureSession {
    pub fn new(prf_results: PrfResults) -> anyhow::Result<Self> {
        let seed = PrivateKeySeed {
            first: prf_results.first,
            second: prf_results.second,
        };

        let private_key = PrivateKey::from_seed(seed)?;

        Ok(Self { private_key })
    }

    pub fn decrypt(&self, cipher: &str) -> anyhow::Result<String> {
        self.private_key.decrypt(cipher)
    }

    pub fn public_key(&self, algorithm: EncryptionAlgorithm) -> PublicKey {
        self.private_key.public_key(algorithm)
    }
}
