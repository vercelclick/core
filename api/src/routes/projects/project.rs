use crate::api_types::HttpResponse;
use crate::projects::{CreateProjectRequest, ListProjectsResult};
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::{Extension, State};
use reqwest::StatusCode;
use secretpass_core::{SpassProject, SpassUser};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn list_projects(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<SpassUser>>,
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

#[axum::debug_handler]
pub async fn create_project(
    State(state): State<ApiState>,
    Extension(package): Extension<Arc<SessionPackage>>,
    Json(request): Json<CreateProjectRequest>,
) -> HttpResponse<Json<SpassProject>> {
    let project = state
        .backend
        .create_project(&package.user, &package.passkeys, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error creating project",
        ))?;

    Ok(Json(project))
}
