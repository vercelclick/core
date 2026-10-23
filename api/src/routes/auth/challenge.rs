use crate::backend::ApiState;
use crate::routes::types::HttpResponse;
use crate::utils::{CloudProxy, error_mapper};
use crate::{CheckChallengeResult, PendingChallenge};
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerateChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerateChallengeResponse {
    pub challenge: String,
}

pub async fn generate_challenge_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<GenerateChallengeRequest>,
) -> HttpResponse<Json<GenerateChallengeResponse>> {
    if state.mode == OperationMode::Local && request.kind.is_cloud_only() {
        let response: GenerateChallengeResponse =
            CloudProxy::new(method, uri).json(&request).proxy().await?;
        return Ok(Json(response));
    }

    let (challenge, pending_challenge) = match request.kind {
        ChallengeKind::EmailSignup | ChallengeKind::EmailSignIn => {
            PendingChallenge::send_email_code(
                request.kind.clone(),
                request.owner,
                state.is_proxied(headers),
            )
            .await
        }
        _ => PendingChallenge::generate_webauthn(request.kind.clone(), request.owner).await,
    }
    .map_err(error_mapper(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("Error generating {} challenge", request.kind),
    ))?;

    state
        .backend
        .record_pending_challenge(pending_challenge)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error recording pending challenge",
        ))?;

    Ok(Json(GenerateChallengeResponse { challenge }))
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CheckChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
    pub value: String,
}

#[axum::debug_handler]
pub async fn check_challenge_handler(
    State(state): State<ApiState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(request): Json<CheckChallengeRequest>,
) -> HttpResponse<Json<CheckChallengeResult>> {
    if !request.kind.is_checkable() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid challenge check request".to_string(),
        ));
    }

    if state.mode == OperationMode::Local && request.kind.is_cloud_only() {
        let challenge: CheckChallengeResult =
            CloudProxy::new(method, uri).json(&request).proxy().await?;
        return Ok(Json(challenge));
    }

    let result = state
        .backend
        .retrieve_pending_challenge_for_attempt(request.kind, request.owner)
        .await
        .map_err(error_mapper(
            StatusCode::BAD_REQUEST,
            "Error checking challenge",
        ))?;
    let valid = result.verify_challenge(request.value);

    Ok(Json(CheckChallengeResult {
        valid,
        attempts_left: result.attempts_left,
    }))
}
