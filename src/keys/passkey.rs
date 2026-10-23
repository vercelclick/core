use crate::enums::PasskeyType;
use crate::utils::bin_decode;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassPasskey {
    pub id: String, // Credential ID
    pub user_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: PasskeyType,
    pub public_key: String, // Base64url-encoded COSE key
    pub created_at: String,
}

impl SecretpassPasskey {
    pub fn id_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bin_decode(&self.id)
    }

    pub fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bin_decode(&self.public_key)
    }
}
