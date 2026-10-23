use crate::api_types::HttpResponse;
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tower_cookies::Cookies;

#[axum::debug_handler]
pub(crate) async fn get_session_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    cookies: Cookies,
) -> HttpResponse<Json<SessionPackage>> {
    let package = get_session(state, headers, cookies).await?;

    Ok(Json(package))
}

pub async fn get_session(
    state: ApiState,
    headers: HeaderMap,
    cookies: Cookies,
) -> HttpResponse<SessionPackage> {
    let session_cookie = cookies
        .get("session_token")
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No active session".to_string()))?;

    let rp_config = state.get_rp_config(headers);

    let package = state
        .backend
        .get_session(rp_config.passkey_type, session_cookie.value().to_string())
        .await
        .map_err(error_mapper(
            StatusCode::UNAUTHORIZED,
            "Error loading session",
        ))?;

    Ok(package)
}
