use crate::backend::ApiState;
use crate::backend::secrets::{CreateAccessKeyRequest, ProjectPathParams};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use click_core::{AccessKey, AuthSession, InternalResult, caller};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_access_key_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateAccessKeyRequest>,
) -> InternalResult<Json<AccessKey>> {
    let auth_result = request.auth_result.clone();
    let result = state
        .backend
        .create_access_key(&session, params, request)
        .await?;

    auth_result.assert_validation(caller!())?;

    Ok(Json(result))
}
