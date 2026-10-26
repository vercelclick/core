use crate::api_types::HttpError;
use crate::constants::SESSION_COOKIE_NAME;
use crate::utils::error_mapper;
use crate::{ApiState, SessionPackage};
use axum::http::StatusCode;
use secretpass_core::SpassSession;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

pub(crate) async fn record_session(
    state: &ApiState,
    response: &SessionPackage,
) -> Result<(), HttpError> {
    state
        .backend
        .record_session(response.clone())
        .await
        .map_err(error_mapper(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error recording session",
        ))
}

pub(crate) fn set_session_cookie(cookies: &Cookies, session: &SpassSession) {
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session.id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .build();
    cookies.add(cookie)
}
