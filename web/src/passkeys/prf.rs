use serde::{Deserialize, Serialize};
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct PrfDeriveConfig {
    pub cred_id: String,
    pub user_id: Uuid,
    pub passkey_id: Uuid,
}

impl PrfDeriveConfig {
    pub(crate) fn get_salts(&self) -> (Vec<String>, Vec<String>) {
        (
            vec![self.user_id.to_string()],
            vec![self.passkey_id.to_string()],
        )
    }
}

pub struct PrfResults {
    pub first: [u8; 32],
    pub second: [u8; 32],
}
