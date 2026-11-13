use crate::backend::ApiState;
use crate::backend::auth::WebauthnChallengeResponse;
use axum::extract::State;
use axum::{Extension, Json};
use click_core::{AuthSession, InternalResult};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn generate_webauthn_challenge_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
) -> InternalResult<Json<WebauthnChallengeResponse>> {
    let challenge = state
        .backend
        .generate_webauthn_authorization_challenge(&session)
        .await?;

    Ok(Json(WebauthnChallengeResponse { challenge }))
}
