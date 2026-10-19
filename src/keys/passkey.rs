use crate::utils::bin_decode;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
pub struct SecretpassPasskey {
    pub id: String, // Credential ID
    pub name: String,
    pub user_id: String,
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
