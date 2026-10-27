use crate::api_types::HttpResponse;
use crate::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::{Extension, Path, State};
use reqwest::StatusCode;
use secretpass_core::{SpassProject, SpassUser};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

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

#[derive(Deserialize)]
pub struct GetProjectByIdRequest {
    pub project_id: Uuid,
}

#[axum::debug_handler]
pub async fn get_project_by_id(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<SpassUser>>,
    Path(request): Path<GetProjectByIdRequest>,
) -> HttpResponse<Json<GetProjectResult>> {
    let project = state
        .backend
        .get_project_by_id(&user, request.project_id)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error fetching project",
        ))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Project not found".to_string()))?;

    Ok(Json(project))
}
