use crate::passkeys::prf::PrfResults;
use secretpass_core::{EncryptionAlgorithm, PrivateKey, PrivateKeySeed};
use std::collections::HashMap;

#[derive(Clone)]
pub struct SecureSession {
    pub algorithm: EncryptionAlgorithm,
    private_key: PrivateKey,
}

impl SecureSession {
    pub fn new(algorithm: EncryptionAlgorithm, prf_results: PrfResults) -> anyhow::Result<Self> {
        let seed = PrivateKeySeed {
            algorithm,
            first: prf_results.first,
            second: prf_results.second,
        };

        let private_key = PrivateKey::from_seed(seed)?;

        Ok(Self {
            algorithm,
            private_key,
        })
    }

    pub fn decrypt(&self, cipher: &str) -> anyhow::Result<Vec<u8>> {
        self.private_key.decrypt(cipher)
    }

    pub fn decrypt_package(
        &self,
        secrets_package: &HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, Vec<u8>>> {
        self.private_key.decrypt_package(secrets_package)
    }
}
