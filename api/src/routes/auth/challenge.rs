use crate::backend::ApiState;
use crate::backend::PendingChallenge;
use axum::Json;
use axum::extract::State;
use secretpass_core::InternalResult;
use secretpass_core::enums::ChallengeKind;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebauthnChallengeRequest {
    pub kind: ChallengeKind,
    pub owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebauthnChallengeResponse {
    pub challenge: String,
}

#[axum::debug_handler]
pub async fn generate_webauthn_challenge_handler(
    State(state): State<ApiState>,
    Json(request): Json<WebauthnChallengeRequest>,
) -> InternalResult<Json<WebauthnChallengeResponse>> {
    let (challenge, pending_challenge) =
        PendingChallenge::generate_webauthn(request.kind, request.owner);

    state
        .backend
        .record_pending_challenge(&pending_challenge)
        .await?;

    Ok(Json(WebauthnChallengeResponse { challenge }))
}
