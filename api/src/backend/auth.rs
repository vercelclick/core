use secretpass_core::enums::PasskeyType;
use secretpass_core::{SecretpassPasskey, SecretpassUser, SecretpassUserSession};
use secretpass_web::{AuthorizationResponse, PasskeyCreationResponse};
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
    pub passkey_response: PasskeyCreationResponse,
    // The user use's the registered passkey to registration
    pub auth_response: AuthorizationResponse,
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
    pub auth_response: AuthorizationResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailLoginRequest {
    pub email_address: String,
    pub confirmation_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct StartLoginRequest {
    pub email_only: bool,
    pub email_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct StartLoginResponse {
    pub challenge: String,
    pub known_credentials: Vec<String>,
}
