use crate::ApiState;
use crate::api_types::HttpResponse;
use crate::environments::SecretWithEncryptedValues;
use crate::secrets::{CreateSecretRequest, ProjectEnvPathParams};
use crate::utils::error_mapper;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::User;
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_secret(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(params): Path<ProjectEnvPathParams>,
    Json(request): Json<CreateSecretRequest>,
) -> HttpResponse<Json<SecretWithEncryptedValues>> {
    // TODO: Verify auth result

    let result = state
        .backend
        .create_secret(&user, params, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error creating secret",
        ))?;

    Ok(Json(result))
}
