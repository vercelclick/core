use crate::backend::ApiState;
use crate::backend::{CheckChallengeResult, PendingChallenge};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult};
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
    Json(request): Json<GenerateChallengeRequest>,
) -> InternalResult<Json<GenerateChallengeResponse>> {
    let user = state.backend.get_user_email(request.owner.clone()).await?;

    if request.kind.is_new_user_only() && user.is_some() {
        return Err(InternalError::new(
            StatusCode::FORBIDDEN,
            "You already have an account under this email address, try to sign in instead.",
        ));
    } else if !request.kind.is_new_user_only() && user.is_none() {
        return Err(InternalError::new(
            StatusCode::BAD_REQUEST,
            "User not found",
        ));
    }

    let (challenge, pending_challenge) = match request.kind {
        ChallengeKind::EmailSignIn => {
            PendingChallenge::send_email_code(request.kind, request.owner, user.unwrap().name, None)
                .await
        }
        ChallengeKind::EmailAuthorize => {
            let operation = request.operation.clone().ok_or_else(|| {
                InternalError::new(
                    StatusCode::BAD_REQUEST,
                    "Operation required for email authorize challenge",
                )
            })?;
            PendingChallenge::send_email_code(
                request.kind,
                request.owner,
                user.unwrap().name,
                Some(operation),
            )
            .await
        }
        ChallengeKind::EmailSignup => {
            let name = request.name.clone().ok_or_else(|| {
                InternalError::new(
                    StatusCode::BAD_REQUEST,
                    "Name missing for email signup challenge",
                )
            })?;
            PendingChallenge::send_email_code(
                request.kind,
                request.owner,
                name,
                request.operation.clone(),
            )
            .await
        }
        _ => Ok(PendingChallenge::generate_webauthn(
            request.kind,
            request.owner,
        )),
    }?;

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
    Json(request): Json<CheckChallengeRequest>,
) -> InternalResult<Json<CheckChallengeResult>> {
    if !request.kind.is_checkable() {
        return Err(InternalError::new(
            StatusCode::BAD_REQUEST,
            "Invalid challenge check request",
        ));
    }

    let result = state
        .backend
        .retrieve_pending_challenge_for_attempt(request.kind, request.owner)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::NOT_FOUND, "Challenge not found"))?;

    let valid = result.verify_challenge(request.value);

    Ok(Json(CheckChallengeResult {
        valid,
        attempts_left: result.attempts_left,
    }))
}
