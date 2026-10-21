use secretpass_core::{SecretpassPasskey, SecretpassUser, SecretpassUserSession};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
#[derive(Debug, Clone, Deserialize, Serialize, Tsify)]
pub struct CreateUserParams {
    pub generated_id: String,
    pub name: String,
    pub email: String,
    pub confirmation_code: String,
    pub passkey: SecretpassPasskey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct SessionResponse {
    pub session: SecretpassUserSession,
    pub user: SecretpassUser,
}
