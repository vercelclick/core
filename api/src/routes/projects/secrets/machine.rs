use crate::ApiState;
use crate::secrets::GetMachineSecretParams;
use axum::Json;
use axum::extract::{Path, State};
use secretpass_core::InternalResult;
use std::collections::HashMap;

pub async fn get_machine_secrets(
    State(state): State<ApiState>,
    Path(params): Path<GetMachineSecretParams>,
) -> InternalResult<Json<HashMap<String, String>>> {
    let response = state.backend.get_machine_secrets(params).await?;

    Ok(Json(response))
}
