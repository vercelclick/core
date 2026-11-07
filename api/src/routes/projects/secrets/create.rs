use crate::api_types::HttpResponse;
use crate::environments::SecretWithEncryptedValues;
use crate::secrets::{
    CreateSecretRequest, ProjectEnvPathParams, ProjectSecretPathParams, UpdateSecretRequest,
    UpdateSecretValueRequest,
};
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use std::sync::Arc;
use secretpass_core::User;

#[axum::debug_handler]
pub async fn create_secret(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectEnvPathParams>,
    Json(request): Json<CreateSecretRequest>,
) -> HttpResponse<Json<SecretWithEncryptedValues>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let result = state
        .backend
        .create_secret(&session.user, params, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error creating secret",
        ))?;

    Ok(Json(result))
}

#[axum::debug_handler]
pub async fn update_secret(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretRequest>,
) -> HttpResponse<Json<SecretWithEncryptedValues>> {
    let response = state
        .backend
        .update_secret(&user, params, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error updating secret",
        ))?;

    Ok(Json(response))
}

#[axum::debug_handler]
pub async fn update_secret_value(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectSecretPathParams>,
    Json(request): Json<UpdateSecretValueRequest>,
) -> HttpResponse<Json<SecretWithEncryptedValues>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let response = state
        .backend
        .update_secret_value(&session.user, params, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error updating secret value",
        ))?;

    Ok(Json(response))
}
