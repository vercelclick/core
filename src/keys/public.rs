use crate::keys::derive::DerivedPublicKey;
use crate::types::EncryptedPackage;
use crate::utils::{bin_decode, bin_encode, fill_random_bytes, get_global_rng};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};

use crate::result::{InternalError, InternalResult};

use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ts_rs::TS;
use uuid::Uuid;
use x25519_dalek::StaticSecret;

#[derive(Clone)]
pub struct PublicKey {
    pub key: DerivedPublicKey,
}

impl PublicKey {
    pub fn from_encoded(encoded_value: &str) -> InternalResult<Self> {
        let bytes = bin_decode(encoded_value)?;
        let key_bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|err| {
            InternalError::trace(StatusCode::CONFLICT, "Invalid public key value", err)
        })?;
        let key = DerivedPublicKey::from(key_bytes);

        Ok(Self { key })
    }

    pub fn encode(&self) -> String {
        bin_encode(&self.key.to_bytes())
    }

    pub fn access_key_id(&self) -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_OID, &self.key.to_bytes())
    }
}

fn generate_nonce_bytes() -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    fill_random_bytes(&mut nonce_bytes);

    nonce_bytes
}

impl PublicKey {
    pub fn encrypt(&self, payload: String) -> InternalResult<String> {
        let nonce_bytes = generate_nonce_bytes();

        let mut rng = get_global_rng().lock().unwrap();
        let encryptor_secret = StaticSecret::random_from_rng(&mut rng);

        let public_key = DerivedPublicKey::from(&encryptor_secret);
        let shared_secret = encryptor_secret.diffie_hellman(&self.key);

        let nonce = Nonce::from(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes()).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error generating encryption cypher",
                err,
            )
        })?;

        let ciphertext = cipher
            .encrypt(&nonce, payload.into_bytes().as_slice())
            .map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error encrypting value",
                    err,
                )
            })?;

        let encrypted_package = EncryptedPackage {
            public_key: public_key.to_bytes(),
            nonce_bytes,
            ciphertext,
        };

        Ok(encrypted_package.encode())
    }

    pub fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, String>,
    ) -> InternalResult<HashMap<String, String>> {
        let mut encrypted_package = HashMap::new();
        for (name, value) in decrypted_package {
            let encrypted_value = self.encrypt(value)?;
            encrypted_package.insert(name, encrypted_value);
        }
        Ok(encrypted_package)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TargetedPublicKey {
    pub target: Uuid,
    pub value: String,
}

impl TargetedPublicKey {
    pub fn public_key(&self) -> InternalResult<PublicKey> {
        PublicKey::from_encoded(&self.value)
    }
}
