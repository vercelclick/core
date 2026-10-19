use crate::PublicKey;
use crate::enums::AccessGrant;
use crate::keys::public::PublicKeyEncrypt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassProjectUserPublicKey {
    pub id: String,
    pub name: String,
    pub passkey_id: String,
    pub project_user_id: String,
    pub access: AccessGrant,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
    pub granted_by: Option<String>,
    pub granted_on: Option<String>, // Set to email of the grantor
    pub created_on: String,
}

impl SecretpassProjectUserPublicKey {
    fn public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_encoded(self.ecc.clone(), self.kem.clone())
    }
}

impl PublicKeyEncrypt for SecretpassProjectUserPublicKey {
    fn encrypt(&self, payload: Vec<u8>) -> anyhow::Result<String> {
        self.public_key()?.encrypt(payload)
    }

    fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<HashMap<String, String>> {
        self.public_key()?.encrypt_package(decrypted_package)
    }
}
