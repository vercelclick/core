use crate::keys::derive::{EccPublicKey, KemPublicKey};
use crate::types::EncryptedPackage;
use crate::utils::{
    bin_decode, bin_encode, bin_serialize, fill_random_bytes, get_global_rng, sha256_digest,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ml_kem::{Encapsulate, KeyExport, TryKeyInit};
use std::collections::HashMap;
use x25519_dalek::StaticSecret;

#[derive(Clone)]
pub struct PublicKey {
    ecc: Option<EccPublicKey>,
    kem: Option<KemPublicKey>,
}

impl PublicKey {
    pub fn from_encoded(ecc: Option<String>, kem: Option<String>) -> anyhow::Result<Self> {
        let kem = match kem {
            Some(value) => {
                let bytes = bin_decode(&value)?;
                let key = KemPublicKey::new_from_slice(&bytes)?;
                Some(key)
            }
            _ => None,
        };

        let ecc = match ecc {
            Some(value) => {
                let bytes = bin_decode(&value)?;
                let key_bytes: [u8; 32] = bytes.as_slice().try_into()?;
                let key = EccPublicKey::from(key_bytes);
                Some(key)
            }
            None => None,
        };

        Ok(Self { kem, ecc })
    }

    pub fn from_keys(ecc: Option<EccPublicKey>, kem: Option<KemPublicKey>) -> Self {
        Self { ecc, kem }
    }

    pub fn ecc(&self) -> Option<String> {
        self.ecc.as_ref().map(|value| bin_encode(&value.to_bytes()))
    }

    pub fn kem(&self) -> Option<String> {
        self.kem
            .as_ref()
            .map(|value| bin_encode(&value.clone().to_bytes()))
    }

    fn get_ecc_aes_keys(&self) -> (Option<Vec<u8>>, Option<[u8; 32]>) {
        if self.ecc.is_none() {
            return (None, None);
        }

        let target_public_key = &self.ecc.unwrap();
        let mut rng = get_global_rng().lock().unwrap();
        let encryptor_secret = StaticSecret::random_from_rng(&mut rng);

        let encryptor_public = EccPublicKey::from(&encryptor_secret);
        let shared_secret = encryptor_secret.diffie_hellman(target_public_key);

        (
            Some(encryptor_public.to_bytes().to_vec()),
            Some(shared_secret.to_bytes()),
        )
    }

    fn get_kem_aes_keys(&self) -> (Option<Vec<u8>>, Option<[u8; 32]>) {
        if self.kem.is_none() {
            return (None, None);
        }

        let mut rng = get_global_rng().lock().unwrap();
        let target_public_key = self.kem.clone().unwrap();
        let (ciphertext, shared_secret) = target_public_key.encapsulate_with_rng(&mut rng);

        (Some(ciphertext.to_vec()), Some(shared_secret.into()))
    }

    fn aes_encrypt_payload(
        nonce: [u8; 12],
        shared_secret: [u8; 32],
        payload: &Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let nonce = Nonce::from(nonce);
        let cipher = Aes256Gcm::new_from_slice(&shared_secret)?;

        let ciphertext = cipher.encrypt(&nonce, payload.as_slice())?;

        Ok(ciphertext)
    }

    // Only applies to machine keys
    pub fn machine_key_id(&self) -> String {
        let mut data = vec![];
        for value in [self.ecc(), self.kem()].iter().flatten() {
            data.push(value.to_string());
        }

        sha256_digest(&data)
    }
}

fn generate_nonce_bytes() -> anyhow::Result<[u8; 12]> {
    let mut nonce_bytes = [0u8; 12];
    fill_random_bytes(&mut nonce_bytes);

    Ok(nonce_bytes)
}

pub trait PublicKeyEncrypt {
    fn encrypt(&self, payload: Vec<u8>) -> anyhow::Result<String>;
    fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<HashMap<String, String>>;
}

impl PublicKeyEncrypt for PublicKey {
    fn encrypt(&self, payload: Vec<u8>) -> anyhow::Result<String> {
        let nonce_bytes = generate_nonce_bytes()?;

        let (ecc_public_key, ecc_shared_secret) = self.get_ecc_aes_keys();
        let (kem_ciphertext, kem_shared_secret) = self.get_kem_aes_keys();
        let mut payload = payload.clone();

        // Order of events - ECC encrypts first decrypts last, KEM encrypts last decrypts first
        for shared_secret in [ecc_shared_secret, kem_shared_secret].into_iter().flatten() {
            payload = Self::aes_encrypt_payload(nonce_bytes, shared_secret, &payload)?
        }

        let encrypted_package =
            EncryptedPackage(ecc_public_key, kem_ciphertext, nonce_bytes, payload);

        bin_serialize(&encrypted_package)
    }

    fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<HashMap<String, String>> {
        let mut encrypted_package = HashMap::new();
        for (name, value) in decrypted_package {
            let encrypted_value = self.encrypt(value)?;
            encrypted_package.insert(name, encrypted_value);
        }
        Ok(encrypted_package)
    }
}
