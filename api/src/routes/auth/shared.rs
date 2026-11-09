use crate::constants::SESSION_COOKIE_NAME;
use crate::{ApiState, SessionPackage};
use secretpass_core::{InternalResult, Session};
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

pub(crate) async fn record_session(
    state: &ApiState,
    response: &SessionPackage,
) -> InternalResult<()> {
    state.backend.record_session(response.clone()).await
}

pub(crate) fn set_session_cookie(cookies: &Cookies, session: &Session) {
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session.id.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .build();
    cookies.add(cookie)
}
