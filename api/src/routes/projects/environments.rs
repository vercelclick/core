use crate::ApiState;
use crate::api_types::HttpResponse;
use crate::environments::{GetEnvironmentRequest, GetEnvironmentResult};
use crate::utils::error_mapper;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::SpassUser;
use std::sync::Arc;

pub async fn get_environment_by_name(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<SpassUser>>,
    Path(request): Path<GetEnvironmentRequest>,
) -> HttpResponse<Json<GetEnvironmentResult>> {
    let result = state
        .backend
        .get_environment_by_name(&user, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error loading environment",
        ))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Environment not found".to_string()))?;

    Ok(Json(result))
}
