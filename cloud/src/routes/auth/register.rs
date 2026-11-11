use crate::auth_session::create_backend_session_token;
use crate::backend::auth::register::create_user;
use crate::routes::user::passkeys::utils::{
    PasskeyCreateValidationRequest, validate_passkey_creation_details,
};
use axum::Json;
use axum::extract::State;
use secretpass_api::backend::ApiState;
use secretpass_api::backend::auth::AuthTokenResponse;
use secretpass_core::InternalResult;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CreateUserRequest {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub user_salt: String,
    pub confirmation_code: String,
    pub passkey_name: String,
    pub passkey_salt: String,
    pub passkey_result: PasskeyCreationResult,
    pub public_key: String,
    pub auth_result: PasskeyAuthorizationResult,
}

#[derive(Debug, Clone)]
pub struct BackendCreateUserRequest {
    pub user_id: Uuid,
    pub user_name: String,
    pub user_salt: String,
    pub user_email: String,
    pub passkey_cred_id: String,
    pub passkey_name: String,
    pub passkey_salt: String,
    pub passkey_public_key: String,
    pub passkey_web_public_key: String,
}

#[axum::debug_handler]
pub async fn create_user_handler(
    State(state): State<ApiState>,
    Json(request): Json<CreateUserRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    // TODO: Add Captcha verification
    let (cred_id, web_public_key) = validate_passkey_creation_details(
        true,
        &state,
        PasskeyCreateValidationRequest {
            create_result: request.passkey_result,
            email_address: request.email.clone(),
            confirmation_code: request.confirmation_code,
            user_id: request.id,
            auth_result: request.auth_result.clone(),
        },
    )
    .await?;

    let (session, user, passkeys) = create_user(BackendCreateUserRequest {
        user_id: request.id,
        user_email: request.email,
        user_name: request.name,
        user_salt: request.user_salt,
        passkey_cred_id: cred_id,
        passkey_name: request.passkey_name,
        passkey_salt: request.passkey_salt,
        passkey_public_key: request.public_key,
        passkey_web_public_key: web_public_key,
    })
    .await?;

    let token = create_backend_session_token(session, user, passkeys)?;

    Ok(Json(AuthTokenResponse { token }))
}
