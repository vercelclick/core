use crate::api_types::HttpResponse;
use crate::constants::SESSION_COOKIE_NAME;
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::Session;
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

#[axum::debug_handler]
pub(crate) async fn get_session_handler(
    Extension(package): Extension<Arc<SessionPackage>>,
) -> HttpResponse<Json<SessionPackage>> {
    Ok(Json((*package).clone()))
}

pub async fn get_session(
    state: &ApiState,
    cookies: &Cookies,
    is_proxied: bool,
) -> HttpResponse<SessionPackage> {
    let session_cookie = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Unauthorized request".to_string()))?;

    let rp_config = state.get_rp_config(is_proxied);

    let session_id = Uuid::parse_str(session_cookie.value())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session ID".to_string()))?;

    let package = state
        .backend
        .get_session(rp_config.passkey_type, session_id)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error loading session",
        ))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Session not found".to_string()))?;

    Ok(package)
}

#[axum::debug_handler]
pub async fn logout_handler(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(session): Extension<Arc<Session>>,
) -> HttpResponse<()> {
    state
        .backend
        .logout_session(&session)
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error logging out of session",
        ))?;

    cookies.remove(Cookie::new(SESSION_COOKIE_NAME, ""));

    Ok(())
}
