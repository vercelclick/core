use crate::ApiState;
use crate::api_types::HttpResponse;
use crate::secrets::GetMachineSecretParams;
use crate::utils::error_mapper;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::collections::HashMap;

pub async fn get_machine_secrets(
    State(state): State<ApiState>,
    Path(params): Path<GetMachineSecretParams>,
) -> HttpResponse<Json<HashMap<String, String>>> {
    let response = state
        .backend
        .get_machine_secrets(params)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error reading machine secrets",
        ))?;

    Ok(Json(response))
}
