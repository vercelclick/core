use crate::ApiState;
use crate::api_types::HttpResponse;
use crate::secrets::{CreateMachinePublicKeyRequest, ProjectPathParams};
use crate::utils::error_mapper;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::{MachinePublicKey, User};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_machine_public_key_handler(
    State(state): State<ApiState>,
    Extension(user): Extension<Arc<User>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateMachinePublicKeyRequest>,
) -> HttpResponse<Json<MachinePublicKey>> {
    // TODO: Verify auth result

    let result = state
        .backend
        .create_machine_public_key(&user, params, request)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error creating public key",
        ))?;

    Ok(Json(result))
}
