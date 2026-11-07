use crate::api_types::HttpResponse;
use crate::auth::BackendCreateUserRequest;
use crate::constants::RpConfig;
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::{CloudProxy, error_mapper};
use crate::{ApiState, CreateUserRequest, SessionPackage};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use tower_cookies::Cookies;
use uuid::Uuid;

#[axum::debug_handler]
pub async fn create_user(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<CreateUserRequest>,
) -> HttpResponse<Json<SessionPackage>> {
    // TODO: Add Captcha verification

    let response = if state.mode == OperationMode::Local {
        let result: SessionPackage = proxy.send_json(&request).await?;

        record_session(&state, &result).await?;

        result
    } else {
        let rp_config = state.get_rp_config(proxy.is_proxied());
        let (cred_id, public_key) = validate_passkey_creation_details(
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
                passkey_ecc: request.public_key_result.ecc,
                passkey_kem: request.public_key_result.kem,
                passkey_public_key: public_key,
            })
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating user",
            ))?
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
) -> HttpResponse<(String, String)> {
    let email_challenge = state
        .backend
        .pop_pending_challenge(
            if is_signup {
                ChallengeKind::EmailSignup
            } else {
                ChallengeKind::EmailAuthorize
            },
            request.email_address.clone(),
        )
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error reading email challenge",
        ))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Email challenge not found".to_string(),
            )
        })?;

    if !email_challenge.verify_challenge(request.confirmation_code) {
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid email confirmation code".to_string(),
        ));
    }

    let passkey_challenge = state
        .backend
        .pop_pending_challenge(
            if is_signup {
                ChallengeKind::PasskeySignup
            } else {
                ChallengeKind::PasskeyCreate
            },
            request.email_address.clone(),
        )
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error reading passkey challenge",
        ))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Passkey challenge not found".to_string(),
            )
        })?;

    let (passkey_cred_id, passkey_public_key) = request
        .create_result
        .validate(
            &passkey_challenge.value_hash,
            rp_config.id,
            rp_config.origin,
        )
        .map_err(error_mapper(
            StatusCode::BAD_REQUEST,
            "Error validating passkey challenge",
        ))?;

    request
        .auth_result
        .validate(
            request.user_id,
            &passkey_public_key,
            &passkey_challenge.value_hash,
            rp_config.id,
            rp_config.origin,
        )
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error  validating passkey authorization",
        ))?;

    Ok((passkey_cred_id, passkey_public_key))
}
