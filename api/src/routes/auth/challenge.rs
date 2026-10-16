use crate::PendingChallenge;
use crate::backend::ApiState;
use crate::routes::types::HttpResponse;
use crate::utils::error_mapper;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use secretpass_core::enums::ChallengeKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerateChallengePrams {
    pub kind: ChallengeKind,
    pub owner: String,
}

pub async fn generate_challenge_handler(
    State(state): State<ApiState>,
    Json(params): Json<GenerateChallengePrams>,
) -> HttpResponse<String> {
    let pending_challenge = PendingChallenge::generate(params.owner, params.kind);

    let challenge = pending_challenge.value.clone();

    state
        .backend
        .pending_challenge_record(pending_challenge)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error recording pending challenge",
        ))?;

    Ok(challenge)
}
