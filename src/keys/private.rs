use crate::keys::derive::{DerivedPrivateKey, DerivedPublicKey, PrivateKeySeed};
use crate::keys::public::PublicKey;
use crate::result::{InternalError, InternalResult};
use crate::source;
use crate::types::EncryptedPackage;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use http::StatusCode;
use std::collections::HashMap;

#[derive(Clone)]
pub struct KeyPair {
    public_key: DerivedPublicKey,
    private_key: DerivedPrivateKey,
}

impl KeyPair {
    pub fn from_seed(seed: PrivateKeySeed) -> InternalResult<Self> {
        let (public_key, private_key) = seed.derive_key_pair()?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn decrypt(&self, payload: &str) -> InternalResult<String> {
        let encrypted_package = EncryptedPackage::decode(payload)?;

        let encryptor_public_key = DerivedPublicKey::from(encrypted_package.public_key);
        let shared_secret = self.private_key.diffie_hellman(&encryptor_public_key);

        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes()).map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::CONFLICT,
                "Invalid shared secret value",
                err,
            )
        })?;
        let nonce = Nonce::from(encrypted_package.nonce_bytes);

        let decrypted_payload = cipher
            .decrypt(&nonce, encrypted_package.ciphertext.as_slice())
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::CONFLICT,
                    "Error decrypting value",
                    err,
                )
            })?;

        String::from_utf8(decrypted_payload).map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::BAD_REQUEST,
                "Invalid project ID",
                err,
            )
        })
    }

    pub fn decrypt_package(
        &self,
        secrets_package: &HashMap<String, String>,
    ) -> InternalResult<HashMap<String, String>> {
        let mut decrypted_secrets = HashMap::new();

        for (key, value) in secrets_package {
            let decrypted_payload = self.decrypt(value)?;
            decrypted_secrets.insert(key.to_string(), decrypted_payload);
        }

        Ok(decrypted_secrets)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.public_key,
        }
    }
}
