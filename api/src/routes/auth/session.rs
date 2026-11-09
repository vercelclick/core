use crate::constants::SESSION_COOKIE_NAME;
use crate::{ApiState, SessionPackage};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use secretpass_core::{InternalError, InternalResult, Session, source};
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

#[axum::debug_handler]
pub(crate) async fn get_session_handler(
    Extension(package): Extension<Arc<SessionPackage>>,
) -> InternalResult<Json<SessionPackage>> {
    Ok(Json((*package).clone()))
}

pub async fn get_session(state: &ApiState, cookies: &Cookies) -> InternalResult<SessionPackage> {
    let session_cookie = cookies.get(SESSION_COOKIE_NAME).ok_or_else(|| {
        InternalError::new(source!(), StatusCode::UNAUTHORIZED, "Unauthorized request")
    })?;

    let session_id = Uuid::parse_str(session_cookie.value()).map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::UNAUTHORIZED,
            "Invalid session ID",
            err,
        )
    })?;

    let package = state
        .backend
        .get_session(session_id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                source!(),
                StatusCode::BAD_REQUEST,
                "Session not found, try signing in",
            )
        })?;

    Ok(package)
}

#[axum::debug_handler]
pub async fn logout_handler(
    State(state): State<ApiState>,
    cookies: Cookies,
    Extension(session): Extension<Arc<Session>>,
) -> InternalResult<()> {
    state.backend.logout_session(&session).await?;

    cookies.remove(Cookie::new(SESSION_COOKIE_NAME, ""));

    Ok(())
}
