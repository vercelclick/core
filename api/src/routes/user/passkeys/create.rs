use crate::auth_session::create_backend_session_token;
use crate::backend::ApiState;
use crate::backend::auth::AuthTokenResponse;
use crate::routes::auth::register::{
    PasskeyCreateValidationRequest, validate_passkey_creation_details,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{AuthSession, InternalError, InternalResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyRequest {
    name: String,
    confirmation_code: String,
    create_response: PasskeyCreationResult,
    public_key_result: PublicKeyGenerateResult,
}

pub async fn create_passkey_handler(
    State(state): State<ApiState>,
    Extension(auth_session): Extension<Arc<AuthSession>>,
    Json(request): Json<CreatePasskeyRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let session = state
        .backend
        .get_session(auth_session.id, auth_session.user.id)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::UNAUTHORIZED, "Session not found"))?;

    let (cred_id, web_public_key) = validate_passkey_creation_details(
        false,
        &state,
        PasskeyCreateValidationRequest {
            create_result: request.create_response,
            email_address: auth_session.user.email.clone(),
            auth_result: request.public_key_result.auth_response.clone(),
            user_id: auth_session.user.id,
            confirmation_code: request.confirmation_code,
        },
    )
    .await?;

    state
        .backend
        .save_passkey(
            &auth_session.user,
            request.name,
            cred_id,
            web_public_key,
            request.public_key_result,
        )
        .await?;

    let (user, passkeys) = state
        .backend
        .retrieve_user_and_known_passkeys(auth_session.user.email.clone())
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
