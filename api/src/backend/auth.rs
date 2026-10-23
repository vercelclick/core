use secretpass_core::enums::PasskeyType;
use secretpass_core::{SecretpassPasskey, SecretpassUser, SecretpassUserSession};
use secretpass_web::{AuthorizationResponse, RegistrationResponse};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CreateUserRequest {
    pub id: String,
    pub name: String,
    pub email: String,
    pub confirmation_code: String,
    pub passkey_name: String,
    pub passkey_response: RegistrationResponse,
}

#[derive(Debug, Clone)]
pub struct BackendCreateUserRequest {
    pub user_id: String,
    pub user_name: String,
    pub user_email: String,
    pub passkey_cred_id: String,
    pub passkey_name: String,
    pub passkey_type: PasskeyType,
    pub passkey_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionPackage {
    pub session: SecretpassUserSession,
    pub user: SecretpassUser,
    pub passkeys: Vec<SecretpassPasskey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PasskeyLoginRequest {
    pub owner: String,
    pub login_response: AuthorizationResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailLoginRequest {
    pub email_address: String,
    pub confirmation_code: String,
}
