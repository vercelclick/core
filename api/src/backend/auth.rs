use secretpass_core::enums::PasskeyType;
use secretpass_core::{SpassPasskey, SpassSession, SpassUser};
use secretpass_web::{PasskeyAuthorizationResult, PasskeyCreationResult, PublicKeyGenerateResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CreateUserRequest {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub confirmation_code: String,
    pub passkey_id: Uuid,
    pub passkey_name: String,
    pub passkey_result: PasskeyCreationResult,
    pub public_key_result: PublicKeyGenerateResult,
}

#[derive(Debug, Clone)]
pub struct BackendCreateUserRequest {
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
    pub passkey_id: Uuid,
    pub passkey_cred_id: String,
    pub passkey_name: String,
    pub passkey_type: PasskeyType,
    pub passkey_ecc: String,
    pub passkey_kem: String,
    pub passkey_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionPackage {
    pub session: Arc<SpassSession>,
    pub user: Arc<SpassUser>,
    pub passkeys: Arc<Vec<SpassPasskey>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PasskeyLoginRequest {
    pub owner: String,
    pub auth_response: PasskeyAuthorizationResult,
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
