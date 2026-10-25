use crate::ApiState;
use crate::api_types::HttpResponse;
use crate::projects::ListProjectsResult;
use crate::utils::error_mapper;
use axum::Json;
use axum::extract::{Extension, State};
use reqwest::StatusCode;
use secretpass_core::SecretpassUser;
use std::sync::Arc;

#[axum::debug_handler]
pub async fn list_projects(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<SecretpassUser>>,
) -> HttpResponse<Json<ListProjectsResult>> {
    let result = state
        .backend
        .list_projects(&user)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error loading projects",
        ))?;

    Ok(Json(result))
}
