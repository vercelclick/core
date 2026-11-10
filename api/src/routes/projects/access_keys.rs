use crate::backend::ApiState;
use crate::backend::auth::validate_passkey_auth;
use crate::backend::secrets::{CreateAccessKeyRequest, ProjectPathParams};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use secretpass_core::{AccessKey, AuthSession, InternalResult};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_access_key_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateAccessKeyRequest>,
) -> InternalResult<Json<AccessKey>> {
    validate_passkey_auth(&session, &state, &request.auth_result).await?;

    let result = state
        .backend
        .create_access_key(&session.user, params, request)
        .await?;

    Ok(Json(result))
}
