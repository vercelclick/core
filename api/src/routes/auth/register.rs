use crate::auth::BackendCreateUserRequest;
use crate::constants::RpConfig;
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::CloudProxy;
use crate::{ApiState, CreateUserRequest, SessionPackage};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::{InternalError, InternalResult, source};
use tower_cookies::Cookies;
use uuid::Uuid;

#[axum::debug_handler]
pub async fn create_user(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<CreateUserRequest>,
) -> InternalResult<Json<SessionPackage>> {
    // TODO: Add Captcha verification

    let response = if state.mode == OperationMode::Local {
        let result: SessionPackage = proxy.send_json(&request).await?;

        record_session(&state, &result).await?;

        result
    } else {
        let rp_config = state.get_rp_config(proxy.is_proxied());
        let (cred_id, web_public_key) = validate_passkey_creation_details(
            true,
            &state,
            rp_config,
            PasskeyCreateValidationRequest {
                create_result: request.passkey_result,
                email_address: request.email.clone(),
                confirmation_code: request.confirmation_code,
                user_id: request.id,
                auth_result: request.public_key_result.auth_response.clone(),
            },
        )
        .await?;

        state
            .backend
            .create_user(BackendCreateUserRequest {
                user_id: request.id,
                user_email: request.email,
                user_name: request.name,
                passkey_type: rp_config.passkey_type,
                passkey_cred_id: cred_id,
                passkey_name: request.passkey_name,
                passkey_public_key: request.public_key_result.public_key,
                passkey_web_public_key: web_public_key,
            })
            .await?
    };

    set_session_cookie(&cookies, &response.session);

    Ok(Json(response))
}

pub struct PasskeyCreateValidationRequest {
    pub user_id: Uuid,
    pub email_address: String,
    pub confirmation_code: String,
    pub create_result: PasskeyCreationResult,
    pub auth_result: PasskeyAuthorizationResult,
}

pub async fn validate_passkey_creation_details(
    is_signup: bool,
    state: &ApiState,
    rp_config: &RpConfig,
    request: PasskeyCreateValidationRequest,
) -> InternalResult<(String, String)> {
    let email_challenge = state
        .backend
        .get_pending_challenge(
            if is_signup {
                ChallengeKind::EmailSignup
            } else {
                ChallengeKind::EmailAuthorize
            },
            request.email_address.clone(),
        )
        .await?
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::NOT_FOUND,
                "Email challenge not found",
            )
        })?;

    if !email_challenge.verify_challenge(request.confirmation_code) {
        return Err(InternalError::new(
            source!(),
            StatusCode::FORBIDDEN,
            "Invalid email confirmation code",
        ));
    }

    let passkey_challenge = state
        .backend
        .get_pending_challenge(
            if is_signup {
                ChallengeKind::PasskeySignup
            } else {
                ChallengeKind::PasskeyCreate
            },
            request.email_address.clone(),
        )
        .await?
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::NOT_FOUND,
                "Passkey challenge not found",
            )
        })?;

    let (passkey_cred_id, passkey_public_key) = request.create_result.validate(
        &passkey_challenge.value_hash,
        rp_config.id,
        rp_config.origin,
    )?;

    request.auth_result.validate(
        request.user_id,
        &passkey_public_key,
        &passkey_challenge.value_hash,
        rp_config.id,
        rp_config.origin,
    )?;

    Ok((passkey_cred_id, passkey_public_key))
}
