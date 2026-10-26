use crate::PublicKey;
use crate::enums::AccessGrant;
use crate::keys::PublicKeyEncrypt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct ProjectUserPasskey {
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
    pub passkey_id: Uuid,
    pub access: AccessGrant,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ecc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kem: Option<String>,
    pub granted_by: Option<String>,
    pub granted_on: Option<DateTime<Utc>>,
}

impl ProjectUserPasskey {
    fn public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_encoded(self.ecc.clone(), self.kem.clone())
    }
}

impl PublicKeyEncrypt for ProjectUserPasskey {
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
