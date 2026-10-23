use crate::api_types::HttpResponse;
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tower_cookies::Cookies;
use uuid::Uuid;

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
    let session_cookie = cookies.get("session_token").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Session cookie missing".to_string(),
        )
    })?;

    let rp_config = state.get_rp_config(&headers);

    let session_id = Uuid::parse_str(session_cookie.value())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid session ID".to_string()))?;

    let package = state
        .backend
        .get_session(rp_config.passkey_type, session_id)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error loading session",
        ))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Session not found".to_string()))?;

    Ok(package)
}
