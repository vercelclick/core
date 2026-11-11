use crate::backend::auth::challenge::attempt_email_challenge;
use crate::backend::auth::user::get_user_by_email;
use crate::emails::{EmailTemplate, send_email};
use axum::Json;
use axum::extract::State;
use secretpass_api::backend::{ApiState, PendingChallenge};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult, StatusCode};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation: Option<String>,
}

#[axum::debug_handler]
pub async fn send_email_challenge_handler(
    State(state): State<ApiState>,
    Json(request): Json<EmailChallengeRequest>,
) -> InternalResult<()> {
    let user = get_user_by_email(request.owner.clone()).await?;

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

    let (code, pending_challenge) =
        PendingChallenge::generate_email_code(request.kind, request.owner.clone());

    let template = match request.kind {
        ChallengeKind::EmailSignIn => EmailTemplate::Confirm {
            subject: "Click Vault Sign in".to_string(),
            name: user.unwrap().name,
            code,
            operation: "attempted to sign in".to_string(),
        },
        ChallengeKind::EmailAuthorize => {
            let operation = request.operation.clone().ok_or_else(|| {
                InternalError::new(
                    StatusCode::BAD_REQUEST,
                    "Operation required for email authorize challenge",
                )
            })?;
            EmailTemplate::Confirm {
                subject: "Click Vault Confirm".to_string(),
                name: user.unwrap().name,
                code,
                operation,
            }
        }
        ChallengeKind::EmailSignup => {
            let name = request.name.clone().ok_or_else(|| {
                InternalError::new(
                    StatusCode::BAD_REQUEST,
                    "Name missing for email signup challenge",
                )
            })?;
            EmailTemplate::Create {
                subject: "Verify your email".to_string(),
                name,
                code,
            }
        }
        _ => {
            return Err(InternalError::new(
                StatusCode::BAD_REQUEST,
                &format!("{} not supported on this endpoint", request.kind),
            ));
        }
    };

    send_email(&request.owner, template).await?;

    state
        .backend
        .record_pending_challenge(&pending_challenge)
        .await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CheckChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CheckChallengeResult {
    pub valid: bool,
    pub attempts_left: i32,
}

#[axum::debug_handler]
pub async fn check_challenge_handler(
    Json(request): Json<CheckChallengeRequest>,
) -> InternalResult<Json<CheckChallengeResult>> {
    if !request.kind.is_checkable() {
        return Err(InternalError::new(
            StatusCode::BAD_REQUEST,
            "Invalid challenge check request",
        ));
    }

    let challenge = attempt_email_challenge(request.kind, &request.owner)
        .await?
        .ok_or_else(|| InternalError::new(StatusCode::NOT_FOUND, "Challenge not found"))?;

    let valid = challenge.verify_challenge(request.value);

    Ok(Json(CheckChallengeResult {
        valid,
        attempts_left: challenge.attempts_left,
    }))
}
