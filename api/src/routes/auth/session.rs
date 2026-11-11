use crate::auth_session::verify_session_token;
use axum::http::{HeaderMap, StatusCode};
use secretpass_core::{AuthSession, InternalError, InternalResult};

pub async fn get_session(headers: &HeaderMap) -> InternalResult<AuthSession> {
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

    let session = verify_session_token(auth_token)?;

    Ok(session)
}
