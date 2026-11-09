use crate::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::{Extension, Path, State};
use reqwest::StatusCode;
use secretpass_core::{InternalError, InternalResult, Project, User, source};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[axum::debug_handler]
pub async fn list_projects(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
) -> InternalResult<Json<ListProjectsResult>> {
    let result = state.backend.list_projects(&user).await?;

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn create_project(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Json(request): Json<CreateProjectRequest>,
) -> InternalResult<Json<Project>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let project = state
        .backend
        .create_project(&session.user, &session.passkeys, request)
        .await?;

    Ok(Json(project))
}

#[derive(Deserialize)]
pub struct GetProjectByIdRequest {
    pub project_id: Uuid,
}

#[axum::debug_handler]
pub async fn get_project_by_id(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(request): Path<GetProjectByIdRequest>,
) -> InternalResult<Json<GetProjectResult>> {
    let project = state
        .backend
        .get_project_by_id(&user, request.project_id)
        .await?
        .ok_or_else(|| InternalError::new(source!(), StatusCode::NOT_FOUND, "Project not found"))?;

    Ok(Json(project))
}
