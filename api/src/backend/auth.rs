use crate::ApiState;
use crate::api_types::HttpError;
use crate::utils::error_mapper;
use axum::http::StatusCode;
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{Passkey, Session, User};
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
    pub passkey_name: String,
    pub passkey_result: PasskeyCreationResult,
    pub public_key_result: PublicKeyGenerateResult,
}

#[derive(Debug, Clone)]
pub struct BackendCreateUserRequest {
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
    pub passkey_cred_id: String,
    pub passkey_name: String,
    pub passkey_type: PasskeyType,
    pub passkey_ecc: String,
    pub passkey_kem: String,
    pub passkey_public_key: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionPackage {
    pub session: Arc<Session>,
    pub user: Arc<User>,
    pub passkeys: Arc<Vec<Passkey>>,
}

impl SessionPackage {
    pub async fn validate_passkey_auth(
        &self,
        state: &ApiState,
        result: &PasskeyAuthorizationResult,
    ) -> Result<(), HttpError> {
        let rp_config = state.get_rp_config(false);
        let challenge = state
            .backend
            .pop_pending_challenge(ChallengeKind::PasskeyAuthorize, self.user.email.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting authorization challenge",
            ))?
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "Passkey challenge not found".to_string(),
                )
            })?;

        let passkey = self
            .passkeys
            .iter()
            .find(|key| key.cred_id.clone() == result.id)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Passkey not found, logout and login, then try again. If this issue persists, please raise a support request".to_string()))?;

        result
            .validate(
                self.user.id,
                &passkey.public_key,
                &challenge.value_hash,
                rp_config.id,
                rp_config.origin,
            )
            .map_err(error_mapper(
                StatusCode::UNAUTHORIZED,
                "Error validating passkey authorization",
            ))
    }
}
