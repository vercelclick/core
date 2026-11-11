use crate::auth_session::create_backend_session_token;
use crate::backend::auth::passkey::retrieve_passkey_by_cred_id;
use crate::backend::auth::session::{create_session_by_email, create_session_by_user_id};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use secretpass_api::backend::ApiState;
use secretpass_api::backend::auth::{AuthTokenResponse, EmailLoginRequest, PasskeyLoginRequest};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult};

pub async fn login_user_with_email(
    State(state): State<ApiState>,
    Json(request): Json<EmailLoginRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let pending_challenge = state
        .backend
        .get_pending_challenge(ChallengeKind::EmailSignIn, &request.email_address)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::BAD_REQUEST, "Email challenge not found"))?;

    if !pending_challenge.verify_challenge(request.confirmation_code) {
        return Err(InternalError::new(
            StatusCode::FORBIDDEN,
            "Invalid confirmation code",
        ));
    }

    let (session, user, passkeys) = create_session_by_email(request.email_address).await?;

    let token = create_backend_session_token(session, user, passkeys)?;

    Ok(Json(AuthTokenResponse { token }))
}

pub async fn login_user_with_passkey(
    State(state): State<ApiState>,
    Json(request): Json<PasskeyLoginRequest>,
) -> InternalResult<Json<AuthTokenResponse>> {
    let pending_challenge = state
        .backend
        .get_pending_challenge(ChallengeKind::PasskeySignIn, &request.owner)
        .await?
        .ok_or_else(|| {
            InternalError::new(StatusCode::BAD_REQUEST, "Passkey challenge not found")
        })?;

    let passkey = retrieve_passkey_by_cred_id(request.auth_response.id.clone(), request.owner)
        .await?
        .ok_or_else(|| {
            InternalError::new(StatusCode::NOT_FOUND, "Passkey not found on your account")
        })?;

    request.auth_response.validate(
        passkey.user_id,
        &passkey.web_public_key,
        &pending_challenge.value_hash,
    )?;

    let (session, user, passkeys) = create_session_by_user_id(passkey.user_id).await?;
    let token = create_backend_session_token(session, user, passkeys)?;

    Ok(Json(AuthTokenResponse { token }))
}
