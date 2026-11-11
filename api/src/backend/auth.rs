use crate::backend::ApiState;
use axum::http::StatusCode;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{AuthSession, InternalError, InternalResult};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

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
pub struct StartLoginResponse {
    pub challenge: String,
    pub known_credentials: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuthTokenResponse {
    pub token: String,
}

pub async fn validate_passkey_auth(
    session: &AuthSession,
    state: &ApiState,
    result: &PasskeyAuthorizationResult,
) -> InternalResult<()> {
    let challenge = state
        .backend
        .get_pending_challenge(ChallengeKind::PasskeyAuthorize, &session.user.email)
        .await?
        .ok_or_else(|| {
            InternalError::new(StatusCode::BAD_REQUEST, "Passkey challenge not found")
        })?;

    let passkey = session
        .passkeys
        .iter()
        .find(|key| key.cred_id.clone() == result.id)
        .ok_or_else(|| InternalError::new(

            StatusCode::BAD_REQUEST,
            "Passkey not found, logout and login, then try again. If this issue persists, please raise a support request"
        ))?;

    result.validate(
        session.user.id,
        &passkey.web_public_key,
        &challenge.value_hash,
    )
}
