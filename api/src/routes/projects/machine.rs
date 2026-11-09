use crate::secrets::{CreateMachinePublicKeyRequest, ProjectPathParams};
use crate::{ApiState, SessionPackage};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use secretpass_core::{InternalResult, MachinePublicKey};
use std::sync::Arc;

#[axum::debug_handler]
pub async fn create_machine_public_key_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<SessionPackage>>,
    Path(params): Path<ProjectPathParams>,
    Json(request): Json<CreateMachinePublicKeyRequest>,
) -> InternalResult<Json<MachinePublicKey>> {
    session
        .validate_passkey_auth(&state, &request.auth_result)
        .await?;

    let result = state
        .backend
        .create_machine_public_key(&session.user, params, request)
        .await?;

    Ok(Json(result))
}
