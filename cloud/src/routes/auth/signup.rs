use crate::backend::auth::register::CreateUserWorkflow;
use crate::backend::auth::user::get_user_by_email;
use crate::db;
use crate::db::workflows::UpsertWebauthnChallengeWorkflow;
use axum::Json;
use click_api::backend::auth::{AuthTokenResponse, WebauthnChallengeResponse};
use click_core::enums::WebauthnChallengeKind;
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::passkeys::create::PasskeyCreationResult;
use click_core::{InternalError, InternalResult, StatusCode, WebauthnChallenge, caller};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct SignupRequest {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub user_salt: String,
    pub confirmation_code: String,
    pub passkey_name: String,
    pub passkey_salt: String,
    pub passkey_result: PasskeyCreationResult,
    pub public_key: String,
    pub auth_result: Arc<PasskeyAuthorizationResult>,
}

#[axum::debug_handler]
pub async fn signup_handler(
    Json(request): Json<SignupRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    // TODO: Add Captcha verification
    let token = db::with_transaction(CreateUserWorkflow { request }).await?;

    Ok(Json(AuthTokenResponse { token }))
}

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct SignupChallengeRequest {
    pub owner: String,
}

#[axum::debug_handler]
pub async fn signup_passkey_challenge(
    Json(request): Json<SignupChallengeRequest>,
) -> InternalResult<Json<WebauthnChallengeResponse>> {
    let user = get_user_by_email(db::pool(), request.owner.clone()).await?;

    user.is_none().ok_or_else(|| {
        InternalError::new(
            caller!(),
            StatusCode::FORBIDDEN,
            "You already have an account under this email address, try to sign in instead.",
        )
    })?;

    let (challenge, hash) = WebauthnChallenge::generate();

    db::with_transaction(UpsertWebauthnChallengeWorkflow {
        owner: request.owner,
        kind: WebauthnChallengeKind::PasskeySignup,
        hash,
    })
    .await?;

    Ok(Json(WebauthnChallengeResponse { challenge }))
}
