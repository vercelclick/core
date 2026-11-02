use crate::backend::ApiState;
use crate::routes::types::HttpResponse;
use crate::utils::{CloudProxy, error_mapper};
use crate::{CheckChallengeResult, PendingChallenge};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::enums::{ChallengeKind, OperationMode};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GenerateChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GenerateChallengeResponse {
    pub challenge: String,
}

#[axum::debug_handler]
pub async fn generate_challenge_handler(
    State(state): State<ApiState>,
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<GenerateChallengeRequest>,
) -> HttpResponse<Json<GenerateChallengeResponse>> {
    if proxy.is_local() && request.kind.is_cloud_only() {
        let response: GenerateChallengeResponse = proxy.send_json(&request).await?;
        return Ok(Json(response));
    }

    let user = state
        .backend
        .get_user_email(request.owner.clone())
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error checking user exists",
        ))?;

    if request.kind.is_new_user_only() && user.is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            "You already have an account under this email address, login in instead.".to_string(),
        ));
    } else if !request.kind.is_new_user_only() && user.is_none() {
        return Err((StatusCode::BAD_REQUEST, "User not found".to_string()));
    }

    let (challenge, pending_challenge) = match request.kind {
        ChallengeKind::EmailSignIn => {
            PendingChallenge::send_email_code(
                request.kind,
                request.owner,
                user.unwrap().name,
                None,
                proxy.is_proxied(),
            )
            .await
        }
        ChallengeKind::EmailAuthorize => {
            let operation = request.operation.clone().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "Operation required for email authorize challenge".to_string(),
                )
            })?;
            PendingChallenge::send_email_code(
                request.kind,
                request.owner,
                user.unwrap().name,
                Some(operation),
                proxy.is_proxied(),
            )
            .await
        }
        ChallengeKind::EmailSignup => {
            let name = request.name.clone().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "Name missing for email signup challenge".to_string(),
                )
            })?;
            PendingChallenge::send_email_code(
                request.kind,
                request.owner,
                name,
                request.operation.clone(),
                proxy.is_proxied(),
            )
            .await
        }
        _ => PendingChallenge::generate_webauthn(request.kind, request.owner).await,
    }
    .map_err(error_mapper(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("Error generating {} challenge", request.kind),
    ))?;

    pending_challenge.record(&state).await?;

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
    Extension(proxy): Extension<CloudProxy>,
    Json(request): Json<CheckChallengeRequest>,
) -> HttpResponse<Json<CheckChallengeResult>> {
    if !request.kind.is_checkable() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid challenge check request".to_string(),
        ));
    }

    if state.mode == OperationMode::Local && request.kind.is_cloud_only() {
        let challenge: CheckChallengeResult = proxy.send_json(&request).await?;
        return Ok(Json(challenge));
    }

    let result = state
        .backend
        .retrieve_pending_challenge_for_attempt(request.kind, request.owner)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error checking challenge",
        ))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Challenge not found".to_string()))?;

    let valid = result.verify_challenge(request.value);

    Ok(Json(CheckChallengeResult {
        valid,
        attempts_left: result.attempts_left,
    }))
}
