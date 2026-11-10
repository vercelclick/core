use crate::backend::secrets::{CreateAccessKeyRequest, ProjectPathParams};
use crate::backend::{ApiState, SessionPackage};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use secretpass_core::{AccessKey, InternalResult};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_access_key_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateAccessKeyRequest>,
) -> InternalResult<Json<AccessKey>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let result = state
        .backend
        .create_access_key(&session.user, params, request)
        .await?;

    Ok(Json(result))
}
