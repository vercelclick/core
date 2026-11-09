use crate::ApiState;
use crate::environments::{GetEnvironmentRequest, GetEnvironmentResult};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::{InternalError, InternalResult, User, source};
use std::sync::Arc;

pub async fn get_environment_by_name(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(request): Path<GetEnvironmentRequest>,
) -> InternalResult<Json<GetEnvironmentResult>> {
    let result = state
        .backend
        .get_environment_by_name(&user, request)
        .await?
        .ok_or_else(|| {
            InternalError::new(source!(), StatusCode::NOT_FOUND, "Environment not found")
        })?;

    Ok(Json(result))
}
