use crate::PublicKey;
use crate::PublicKeyEncrypt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use ts_rs::TS;
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SimpleMachinePublicKey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct MachinePublicKey {
    pub id: String,
    pub name: String,
    pub description: String,
    pub project_id: Vec<String>,
    pub environments: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
    pub generated_by: String, // Set to the email of the generator
    pub generated_on: DateTime<Utc>,
}

impl MachinePublicKey {
    pub fn can_access(&self, env: &String) -> bool {
        self.environments.contains(env)
    }
}

impl SimpleMachinePublicKey {
    fn public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_encoded(self.ecc.clone(), self.kem.clone())
    }
}

impl PublicKeyEncrypt for SimpleMachinePublicKey {
    fn encrypt(&self, payload: String) -> anyhow::Result<String> {
        self.public_key()?.encrypt(payload)
    }

    fn encrypt_package(
        &self,
        decrypted_package: HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, String>> {
        self.public_key()?.encrypt_package(decrypted_package)
    }
}
