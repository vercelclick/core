use crate::backend::ApiState;
use crate::backend::environments::{
    CreateEnvironmentRequest, GetEnvironmentRequest, GetEnvironmentResult,
};
use crate::backend::secrets::ProjectPathParams;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use click_core::{AuthSession, InternalError, InternalResult, caller};
use std::sync::Arc;

pub async fn get_environment_by_name(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(request): Path<GetEnvironmentRequest>,
) -> InternalResult<Json<GetEnvironmentResult>> {
    let result = state
        .backend
        .get_environment_by_name(&session, request)
        .await?
        .ok_or_else(|| {
            InternalError::new(caller!(), StatusCode::NOT_FOUND, "Environment not found")
        })?;

    Ok(Json(result))
}

pub async fn create_environment(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateEnvironmentRequest>,
) -> InternalResult<Json<GetEnvironmentResult>> {
    let auth_result = request.auth_result.clone();
    let result = state
        .backend
        .create_environment(&session, params.project_id, request)
        .await?;

    auth_result.assert_validation(caller!())?;

    Ok(Json(result))
}
