use crate::api_types::HttpResponse;
use crate::auth::BackendCreateUserRequest;
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::{CloudProxy, error_mapper};
use crate::{ApiState, CreateUserRequest, SessionPackage};
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use tower_cookies::Cookies;

#[axum::debug_handler]
pub async fn create_user(
    State(state): State<ApiState>,
    cookies: Cookies,
    method: Method,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<CreateUserRequest>,
) -> HttpResponse<Json<SessionPackage>> {
    // No authentication needed for this call - for now
    // TODO: Add Captcha verification

    let response = if state.mode == OperationMode::Local {
        let result: SessionPackage = CloudProxy::new(method, uri).json(&request).proxy().await?;

        record_session(&state, &result).await?;

        result
    } else {
        let request = verify_registration_details(&state, headers, request).await?;

        state
            .backend
            .create_user(request)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating user",
            ))?
    };

    set_session_cookie(&cookies, &response.session);

    Ok(Json(response))
}

async fn verify_registration_details(
    state: &ApiState,
    headers: HeaderMap,
    request: CreateUserRequest,
) -> HttpResponse<BackendCreateUserRequest> {
    let rp_config = state.get_rp_config(headers);
    let email_challenge = state
        .backend
        .pop_pending_challenge(ChallengeKind::EmailSignup, request.email.clone())
        .await
        .map_err(error_mapper(
            StatusCode::BAD_REQUEST,
            "Error reading email challenge",
        ))?;

    if email_challenge.verify_challenge(request.confirmation_code) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid email confirmation code".to_string(),
        ));
    }

    let passkey_challenge = state
        .backend
        .pop_pending_challenge(ChallengeKind::PasskeySignup, request.email.clone())
        .await
        .map_err(error_mapper(
            StatusCode::BAD_REQUEST,
            "Error reading passkey challenge",
        ))?;

    let (passkey_cred_id, passkey_public_key) = request
        .passkey_response
        .validate(
            passkey_challenge.value_hash,
            rp_config.id.to_string(),
            rp_config.origin.to_string(),
        )
        .map_err(error_mapper(
            StatusCode::BAD_REQUEST,
            "Error validating passkey challenge",
        ))?;

    let create_request = BackendCreateUserRequest {
        user_id: request.id,
        user_email: request.email,
        user_name: request.name,
        passkey_type: rp_config.passkey_type.clone(),
        passkey_cred_id,
        passkey_public_key,
        passkey_name: request.passkey_name,
    };

    Ok(create_request)
}
