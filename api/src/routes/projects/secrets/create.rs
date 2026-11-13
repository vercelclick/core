use crate::backend::ApiState;
use crate::backend::environments::SecretWithEncryptedValues;
use crate::backend::secrets::{
    CreateSecretRequest, ProjectEnvPathParams, ProjectSecretPathParams, UpdateSecretRequest,
    UpdateSecretValueRequest,
};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use click_core::{AuthSession, InternalResult, caller};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_secret(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectEnvPathParams>,
    Json(request): Json<CreateSecretRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    let auth_result = request.auth_result.clone();
    let result = state
        .backend
        .create_secret(&session, params, request)
        .await?;

    auth_result.assert_validation(caller!())?;

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn update_secret(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    let response = state
        .backend
        .update_secret(&session, params, request)
        .await?;

    Ok(Json(response))
}

#[axum::debug_handler]
pub async fn update_secret_value(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<AuthSession>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretValueRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    let auth_result = request.auth_result.clone();

    let response = state
        .backend
        .update_secret_value(&session, params, request)
        .await?;

    auth_result.assert_validation(caller!())?;

    Ok(Json(response))
}
