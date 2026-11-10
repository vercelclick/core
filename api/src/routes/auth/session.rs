use crate::auth_session::verify_frontend_session_token;
use crate::backend::ApiState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use secretpass_core::{AuthSession, InternalError, InternalResult, Session};
use std::sync::Arc;

#[axum::debug_handler]
pub(crate) async fn get_session_handler(
    Extension(session): Extension<Arc<AuthSession>>,
) -> InternalResult<Json<AuthSession>> {
    Ok(Json((*session).clone()))
}

pub async fn get_session(
    state: &ApiState,
    path: &str,
    headers: &HeaderMap,
) -> InternalResult<AuthSession> {
    let auth_header = headers
        .get("Authorization")
        .ok_or_else(|| {
            InternalError::new(StatusCode::UNAUTHORIZED, "Missing authorization header")
        })?
        .to_str()
        .map_err(|err| {
            InternalError::trace(
                StatusCode::BAD_REQUEST,
                "Invalid authorization header, valid ASCII string expected",
                err,
            )
        })?;

    let auth_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        InternalError::new(
            StatusCode::BAD_REQUEST,
            "Invalid authorization header, bearer token expected",
        )
    })?;

    let session = verify_frontend_session_token(auth_token, path)?;

    state
        .backend
        .get_session(session.id, session.user.id)
        .await?
        .ok_or_else(|| {
            InternalError::new(
                StatusCode::UNAUTHORIZED,
                "Session has been revoked, please login again",
            )
        })?;

    Ok(session)
}

#[axum::debug_handler]
pub async fn logout_handler(
    State(state): State<ApiState>,
    Extension(session): Extension<Arc<Session>>,
) -> InternalResult<()> {
    state.backend.logout_session(&session).await?;

    Ok(())
}
