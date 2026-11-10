use crate::backend::environments::SecretWithEncryptedValues;
use crate::backend::secrets::{
    CreateSecretRequest, ProjectEnvPathParams, ProjectSecretPathParams, UpdateSecretRequest,
    UpdateSecretValueRequest,
};
use crate::backend::{ApiState, SessionPackage};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use secretpass_core::{InternalResult, User};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_secret(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectEnvPathParams>,
    Json(request): Json<CreateSecretRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let result = state
        .backend
        .create_secret(&session.user, params, request)
        .await?;

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn update_secret(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    let response = state.backend.update_secret(&user, params, request).await?;

    Ok(Json(response))
}

#[axum::debug_handler]
pub async fn update_secret_value(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretValueRequest>,
) -> InternalResult<Json<SecretWithEncryptedValues>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let response = state
        .backend
        .update_secret_value(&session.user, params, request)
        .await?;

    Ok(Json(response))
}
