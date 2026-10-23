use crate::api_types::HttpResponse;
use crate::auth::{EmailLoginRequest, PasskeyLoginRequest};
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::{CloudProxy, error_mapper};
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use tower_cookies::Cookies;

pub async fn login_user_with_email(
    State(state): State<ApiState>,
    cookies: Cookies,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<EmailLoginRequest>,
) -> HttpResponse<Json<SessionPackage>> {
    let result = if state.mode == OperationMode::Local {
        let result: SessionPackage = CloudProxy::new(method, uri).json(&request).proxy().await?;
        record_session(&state, &result).await?;

        result
    } else {
        let pending_challenge = state
            .backend
            .pop_pending_challenge(ChallengeKind::EmailSignIn, request.email_address.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error retrieving challenge",
            ))?;

        if !pending_challenge.verify_challenge(request.confirmation_code) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid confirmation code".to_string(),
            ));
        }

        let rp_config = state.get_rp_config(headers);

        state
            .backend
            .create_session_by_email(rp_config.passkey_type.clone(), request.email_address)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error login in",
            ))?
    };

    set_session_cookie(&cookies, &result.session);

    Ok(Json(result))
}

pub async fn login_user_with_passkey(
    State(state): State<ApiState>,
    cookies: Cookies,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<PasskeyLoginRequest>,
) -> HttpResponse<Json<SessionPackage>> {
    let result = if state.mode == OperationMode::Local {
        let result: SessionPackage = CloudProxy::new(method, uri).json(&request).proxy().await?;

        record_session(&state, &result).await?;
        result
    } else {
        let pending_challenge = state
            .backend
            .pop_pending_challenge(ChallengeKind::PasskeyLogin, request.owner.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error retrieving challenge",
            ))?;
        let rp_config = state.get_rp_config(headers);
        let (user_id, public_key) = state
            .backend
            .retrieve_user_id_and_public_key(
                rp_config.passkey_type.clone(),
                request.login_response.id.clone(),
            )
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error retrieving public key",
            ))?;

        request
            .login_response
            .validate(
                user_id.clone(),
                public_key,
                pending_challenge.value_hash,
                rp_config.id.to_string(),
                rp_config.origin.to_string(),
            )
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error validating passkey response",
            ))?;

        state
            .backend
            .create_session_by_user_and_cred_id(
                rp_config.passkey_type.clone(),
                user_id,
                request.login_response.id,
            )
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating user",
            ))?
    };

    set_session_cookie(&cookies, &result.session);

    Ok(Json(result))
}
