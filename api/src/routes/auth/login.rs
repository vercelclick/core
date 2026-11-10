use crate::backend::auth::{
    EmailLoginRequest, PasskeyLoginRequest, StartLoginRequest, StartLoginResponse,
};
use crate::backend::{ApiState, PendingChallenge, SessionPackage};
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::CloudProxy;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult};
use tower_cookies::Cookies;

pub async fn login_user_with_email(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<EmailLoginRequest>,
) -> InternalResult<Json<SessionPackage>> {
    let result = if proxy.is_local() {
        let result: SessionPackage = proxy.send_json(&request).await?;
        record_session(&state, &result).await?;

        result
    } else {
        let pending_challenge = state
            .backend
            .get_pending_challenge(ChallengeKind::EmailSignIn, request.email_address.clone())
            .await?
            .ok_or_else(|| {
                InternalError::new(StatusCode::BAD_REQUEST, "Email challenge not found")
            })?;

        if !pending_challenge.verify_challenge(request.confirmation_code) {
            return Err(InternalError::new(
                StatusCode::FORBIDDEN,
                "Invalid confirmation code",
            ));
        }

        state
            .backend
            .create_session_by_email(request.email_address)
            .await?
    };

    set_session_cookie(&cookies, &result.session);

    Ok(Json(result))
}

pub async fn login_user_with_passkey(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<PasskeyLoginRequest>,
) -> InternalResult<Json<SessionPackage>> {
    let result = if proxy.is_local() {
        let result: SessionPackage = proxy.send_json(&request).await?;

        record_session(&state, &result).await?;
        result
    } else {
        let pending_challenge = state
            .backend
            .get_pending_challenge(ChallengeKind::PasskeySignIn, request.owner.clone())
            .await?
            .ok_or_else(|| {
                InternalError::new(StatusCode::BAD_REQUEST, "Passkey challenge not found")
            })?;

        let passkey = state
            .backend
            .retrieve_passkey_by_cred_id(request.auth_response.id.clone(), request.owner.clone())
            .await?
            .ok_or_else(|| {
                InternalError::new(StatusCode::NOT_FOUND, "Passkey not found on your account")
            })?;

        request.auth_response.validate(
            passkey.user_id,
            &passkey.web_public_key,
            &pending_challenge.value_hash,
        )?;

        state
            .backend
            .create_session_by_user_id(passkey.user_id)
            .await?
    };

    set_session_cookie(&cookies, &result.session);

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn start_login(
    State(state): State<ApiState>,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<StartLoginRequest>,
) -> InternalResult<Json<StartLoginResponse>> {
    if proxy.is_local() {
        let result: StartLoginResponse = proxy.send_json(&request).await?;
        return Ok(Json(result));
    }

    let (user, passkeys) = state
        .backend
        .retrieve_user_and_known_passkeys(request.email_address)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                StatusCode::NOT_FOUND,
                "User not found, try a different email or create a new account",
            )
        })?;

    let (challenge, pending_challenge) = if request.email_only || passkeys.is_empty() {
        PendingChallenge::send_email_code(
            ChallengeKind::EmailSignIn,
            user.email,
            user.name,
            None,
            proxy.is_proxied(),
        )
        .await?
    } else {
        PendingChallenge::generate_webauthn(ChallengeKind::PasskeySignIn, user.email)
    };

    pending_challenge.record(&state).await?;

    Ok(Json(StartLoginResponse {
        challenge,
        known_credentials: passkeys.iter().map(|pk| pk.cred_id.clone()).collect(),
    }))
}
