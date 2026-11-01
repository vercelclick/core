use crate::enums::EncryptionAlgorithm;
use crate::keys::derive::{
    EccPrivateKey, EccPublicKey, KemPrivateKey, KemPublicKey, PrivateKeySeed,
};
use crate::keys::public::PublicKey;
use crate::types::EncryptedPackage;
use crate::utils::bin_deserialize;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ml_kem::Decapsulate;
use std::collections::HashMap;

#[derive(Clone)]
pub struct PrivateKey {
    ecc: EccPrivateKey,
    ecc_public: EccPublicKey,
    kem: KemPrivateKey,
    kem_public: KemPublicKey,
}

impl PrivateKey {
    pub fn from_seed(seed: PrivateKeySeed) -> anyhow::Result<Self> {
        let (ecc_public_key, ecc_private_key) = seed.derive_ecc_keys()?;

        let (kem_public_key, ken_private_key) = seed.derive_kem_keys()?;

        let private_key = Self {
            ecc: ecc_private_key,
            ecc_public: ecc_public_key,
            kem: ken_private_key,
            kem_public: kem_public_key,
        };

        Ok(private_key)
    }

    pub fn decrypt(&self, payload: &str) -> anyhow::Result<String> {
        let encrypted_package: EncryptedPackage = bin_deserialize(payload)?;

        let ecc_shared_secret = self.get_ecc_aes_shared_secret(&encrypted_package);
        let kem_shared_secret = self.get_kem_aes_shared_secret(&encrypted_package);
        let mut decrypted_payload = encrypted_package.3.clone();

        for shared_secret in [kem_shared_secret, ecc_shared_secret].into_iter().flatten() {
            decrypted_payload =
                Self::aes_decrypt_payload(encrypted_package.2, &shared_secret, decrypted_payload)?
        }

        Ok(String::from_utf8(decrypted_payload)?)
    }

    pub fn decrypt_package(
        &self,
        secrets_package: &HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, String>> {
        let mut decrypted_secrets = HashMap::new();

        for (key, value) in secrets_package {
            let decrypted_payload = self.decrypt(value)?;
            decrypted_secrets.insert(key.to_string(), decrypted_payload);
        }

        Ok(decrypted_secrets)
    }

    fn aes_decrypt_payload(
        nonce: [u8; 12],
        shared_secret: &[u8; 32],
        payload: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(shared_secret)?;
        let nonce = Nonce::from(nonce);

        let decrypted_payload = cipher.decrypt(&nonce, payload.as_slice())?;

        Ok(decrypted_payload)
    }

    fn get_ecc_aes_shared_secret(&self, encrypted_package: &EncryptedPackage) -> Option<[u8; 32]> {
        encrypted_package.0.as_ref()?;

        let encryptor_public_key = EccPublicKey::from(encrypted_package.ecc_public_key());

        let shared_secret = self.ecc.diffie_hellman(&encryptor_public_key);

        Some(shared_secret.to_bytes())
    }

    fn get_kem_aes_shared_secret(&self, encrypted_package: &EncryptedPackage) -> Option<[u8; 32]> {
        encrypted_package.1.as_ref()?;

        let ciphertext = encrypted_package.kem_ciphertext();

        let shared_secret = self.kem.decapsulate(&ciphertext.into());

        Some(shared_secret.into())
    }

    pub fn public_key(&self, algorithm: EncryptionAlgorithm) -> PublicKey {
        let ecc = if algorithm.is_ecc() {
            Some(self.ecc_public)
        } else {
            None
        };
        let kem = if algorithm.is_kem() {
            Some(self.kem_public.clone())
        } else {
            None
        };
        PublicKey::from_keys(ecc, kem)
    }
}
