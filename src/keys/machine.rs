use crate::PublicKey;
use crate::keys::public::PublicKeyEncrypt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassProjectMachinePublicKey {
    pub id: String,
    pub name: String,
    pub description: String,
    pub environments: Vec<String>,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
    pub generated_by: String, // Set to the email of the generator
    pub generated_on: String,
}

impl SecretpassProjectMachinePublicKey {
    fn public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_encoded(self.ecc.clone(), self.kem.clone())
    }
}

impl PublicKeyEncrypt for SecretpassProjectMachinePublicKey {
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
