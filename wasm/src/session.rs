use crate::passkeys::prf::PrfResults;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::{PrivateKey, PrivateKeySeed, PublicKey};
use std::collections::HashMap;

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

    pub fn decrypt_package(
        &self,
        secrets_package: &HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, String>> {
        self.private_key.decrypt_package(secrets_package)
    }

    pub fn public_key(&self, algorithm: EncryptionAlgorithm) -> PublicKey {
        self.private_key.public_key(algorithm)
    }
}
