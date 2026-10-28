use crate::api_types::HttpResponse;
use crate::routes::auth::challenge::GenerateChallengeResponse;
use crate::routes::auth::register::{
    PasskeyCreateValidationRequest, validate_passkey_creation_details,
};
use crate::utils::{CloudProxy, error_mapper};
use crate::{ApiState, PendingChallenge, SessionPackage};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{Passkey, User};
use secretpass_web::{PasskeyAuthorizationResult, PasskeyCreationResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyRequest {
    name: String,
    confirmation_code: String,
    auth_response: PasskeyAuthorizationResult,
    create_response: PasskeyCreationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreatePasskeyResponse {
    passkey: Passkey,
}

pub async fn create_passkey_start_handler(
    State(state): State<ApiState>,
    Extension(proxy): Extension<CloudProxy>,
    Extension(user): Extension<Arc<User>>,
) -> HttpResponse<Json<GenerateChallengeResponse>> {
    if proxy.is_local() {
        let result: GenerateChallengeResponse = proxy.send().await?;
        return Ok(Json(result));
    }

    let (challenge, passkey_challenge) =
        PendingChallenge::generate_webauthn(ChallengeKind::PasskeyCreate, user.email.clone())
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error generating passkey challenge",
            ))?;

    state
        .backend
        .record_pending_challenge(&passkey_challenge)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error recording passkey challenge",
        ))?;

    let (_, email_challenge) = PendingChallenge::send_email_code(
        ChallengeKind::EmailAuthorize,
        user.email.clone(),
        proxy.is_proxied(),
    )
    .await
    .map_err(error_mapper(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error sending email confirmation code",
    ))?;

    state
        .backend
        .record_pending_challenge(&email_challenge)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error recording email challenge",
        ))?;

    Ok(Json(GenerateChallengeResponse { challenge }))
}

pub async fn create_passkey_complete_handler(
    State(state): State<ApiState>,
    Extension(proxy): Extension<CloudProxy>,
    Extension(package): Extension<Arc<SessionPackage>>,
    Json(request): Json<CreatePasskeyRequest>,
) -> HttpResponse<Json<CreatePasskeyResponse>> {
    if proxy.is_local() {
        let result: CreatePasskeyResponse = proxy.send_json(&request).await?;

        let mut passkeys = (*package.passkeys).clone();

        passkeys.push(result.passkey.clone());
        state.backend.record_session(SessionPackage{
            user: package.user.clone(),
            passkeys: Arc::new(passkeys),
            session: package.session.clone()
        }).await.map_err(error_mapper(
            StatusCode::UNAUTHORIZED, // Intentionally send unauthorized to trigger an auth flow
            "Passkey was successfully created but current session could not be updated, try logging in and out"
        ))?;

        return Ok(Json(result));
    }

    let rp_config = state.get_rp_config(proxy.is_proxied());

    let (cred_id, public_key) = validate_passkey_creation_details(
        false,
        &state,
        rp_config,
        PasskeyCreateValidationRequest {
            create_result: request.create_response,
            email_address: package.user.email.clone(),
            auth_result: request.auth_response,
            user_id: package.user.id,
            confirmation_code: request.confirmation_code,
        },
    )
    .await?;

    let passkey = state
        .backend
        .save_passkey(
            &package.user,
            rp_config.passkey_type,
            request.name,
            cred_id,
            public_key,
        )
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error saving passkey",
        ))?;

    Ok(Json(CreatePasskeyResponse { passkey }))
}
