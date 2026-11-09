use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct PrfDeriveConfig {
    pub cred_id: String,
    pub user_salt: String,
    pub passkey_salt: String,
}

impl PrfDeriveConfig {
    pub(crate) fn get_salts(&self) -> (Vec<String>, Vec<String>) {
        (
            vec![self.user_salt.to_string()],
            vec![self.passkey_salt.clone()],
        )
    }
}

pub struct PrfResults {
    pub first: [u8; 32],
    pub second: [u8; 32],
}
