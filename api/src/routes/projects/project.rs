use crate::backend::ApiState;
use crate::backend::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use axum::Json;
use axum::extract::{Extension, Path, State};
use click_core::{AuthSession, InternalError, InternalResult, Project, StatusCode, User, caller};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[axum::debug_handler]
pub async fn list_projects(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
) -> InternalResult<Json<ListProjectsResult>> {
    let result = state.backend.list_projects(&session.user).await?;

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn create_project(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Json(request): Json<CreateProjectRequest>,
) -> InternalResult<Json<Project>> {
    let auth_result = request.auth_result.clone();
    let project = state
        .backend
        .create_project(&session.user, &session.passkeys, request)
        .await?;

    auth_result.assert_validation()?;

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
        .ok_or_else(|| InternalError::new(caller!(), StatusCode::NOT_FOUND, "Project not found"))?;

    Ok(Json(project))
}
