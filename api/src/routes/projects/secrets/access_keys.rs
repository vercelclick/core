use crate::ApiState;
use crate::secrets::{ProjectAccessKeyParams, ProjectSecretPathParams};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use secretpass_core::{InternalResult, TargetedPublicKey, User};
use std::collections::HashMap;
use std::sync::Arc;

#[axum::debug_handler]
pub async fn get_access_key_secrets(
    State(state): State<ApiState>,
    Path(params): Path<ProjectAccessKeyParams>,
) -> InternalResult<Json<HashMap<String, String>>> {
    let response = state.backend.get_access_key_secrets(params).await?;

    Ok(Json(response))
}

#[axum::debug_handler]
pub async fn get_secret_targets(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(params): Path<ProjectSecretPathParams>,
) -> InternalResult<Json<Vec<TargetedPublicKey>>> {
    let targets = state.backend.get_secret_targets(&user, &params).await?;

    Ok(Json(targets))
}
