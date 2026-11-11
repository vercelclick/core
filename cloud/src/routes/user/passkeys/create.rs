use crate::auth_session::create_backend_session_token;
use crate::backend::auth::session::get_session;
use crate::backend::auth::user::get_user_by_email_with_passkeys;
use crate::backend::projects::passkeys::SavePasskeyWorkflow;
use crate::db;
use crate::routes::user::passkeys::utils::{
    PasskeyCreateValidationRequest, validate_passkey_creation_details,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_api::backend::ApiState;
use secretpass_api::backend::auth::AuthTokenResponse;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::{AuthSession, InternalError, InternalResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyRequest {
    name: String,
    salt: String,
    confirmation_code: String,
    create_result: PasskeyCreationResult,
    public_key: String,
    auth_result: PasskeyAuthorizationResult,
}

pub async fn create_passkey_handler(
    State(state): State<ApiState>,
    Extension(auth_session): Extension<Arc<AuthSession>>,
    Json(request): Json<CreatePasskeyRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let session = get_session(auth_session.id, auth_session.user.id)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::UNAUTHORIZED, "Session not found"))?;

    let (cred_id, web_public_key) = validate_passkey_creation_details(
        false,
        &state,
        PasskeyCreateValidationRequest {
            create_result: request.create_result,
            email_address: auth_session.user.email.clone(),
            auth_result: request.auth_result.clone(),
            user_id: auth_session.user.id,
            confirmation_code: request.confirmation_code,
        },
    )
    .await?;

    db::with_transaction(SavePasskeyWorkflow {
        user_id: auth_session.user.id,
        name: request.name,
        cred_id,
        web_public_key,
        salt: request.salt,
        public_key: request.public_key,
    })
    .await?;

    let (user, passkeys) = get_user_by_email_with_passkeys(auth_session.user.email.clone())
        .await?
        .ok_or_else(|| {
            InternalError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "User not found for a verified session",
            )
        })?;

    let token = create_backend_session_token(session, user, passkeys)?;

    Ok(Json(AuthTokenResponse { token }))
}
