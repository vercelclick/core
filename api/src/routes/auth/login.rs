use crate::api_types::HttpResponse;
use crate::auth::{EmailLoginRequest, PasskeyLoginRequest, StartLoginRequest, StartLoginResponse};
use crate::routes::auth::shared::{record_session, set_session_cookie};
use crate::utils::{CloudProxy, error_mapper};
use crate::{ApiState, PendingChallenge, SessionPackage};
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
            ))?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    "Email challenge not found".to_string(),
                )
            })?;

        if !pending_challenge.verify_challenge(request.confirmation_code) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid confirmation code".to_string(),
            ));
        }

        let rp_config = state.get_rp_config(&headers);

        state
            .backend
            .create_session_by_email(rp_config.passkey_type, request.email_address)
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
            .pop_pending_challenge(ChallengeKind::PasskeySignIn, request.owner.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error retrieving challenge",
            ))?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    "Passkey challenge not found".to_string(),
                )
            })?;

        let rp_config = state.get_rp_config(&headers);
        let (user_id, public_key) = state
            .backend
            .retrieve_user_id_and_public_key(
                rp_config.passkey_type,
                request.auth_response.id.clone(),
            )
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error retrieving public key",
            ))?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    "Passkey not found on your account".to_string(),
                )
            })?;

        request
            .auth_response
            .validate(
                user_id.to_string(),
                public_key,
                pending_challenge.value_hash,
                rp_config.id.to_string(),
                rp_config.origin.to_string(),
            )
            .map_err(error_mapper(
                StatusCode::CONFLICT,
                "Passkey authenticity could not be ascertained",
            ))?;

        state
            .backend
            .create_session_by_user_id(rp_config.passkey_type, user_id)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating user",
            ))?
    };

    set_session_cookie(&cookies, &result.session);

    Ok(Json(result))
}

pub async fn start_login(
    State(state): State<ApiState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<StartLoginRequest>,
) -> HttpResponse<Json<StartLoginResponse>> {
    if state.mode == OperationMode::Local {
        let result: StartLoginResponse =
            CloudProxy::new(method, uri).json(&request).proxy().await?;
        return Ok(Json(result));
    }

    let rp_config = state.get_rp_config(&headers);
    let (user, passkeys) = state
        .backend
        .retrieve_user_and_known_passkeys(request.email_address, rp_config.passkey_type)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error retrieving user",
        ))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "User not found, try a different email or create a new account".to_string(),
            )
        })?;

    let (challenge, pending_challenge) = if request.email_only || passkeys.is_empty() {
        PendingChallenge::send_email_code(
            ChallengeKind::EmailSignIn,
            user.email,
            state.is_proxied(&headers),
        )
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error generating confirmation code",
        ))?
    } else {
        PendingChallenge::generate_webauthn(ChallengeKind::PasskeySignIn, user.email)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error generating passkey challenge",
            ))?
    };

    pending_challenge.record(&state).await?;

    Ok(Json(StartLoginResponse {
        challenge,
        known_credentials: passkeys.iter().map(|pk| pk.id.clone()).collect(),
    }))
}
