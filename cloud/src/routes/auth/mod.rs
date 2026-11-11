use axum::Router;
use axum::routing::post;
use secretpass_api::backend::ApiState;

mod challenge;
mod login;
pub mod register;

pub fn auth_router() -> Router<ApiState> {
    Router::new()
        .route("/register", post(register::create_user_handler))
        .route("/login/email", post(login::login_user_with_email))
        .route("/login/passkey", post(login::login_user_with_passkey))
        .route(
            "/challenge/email",
            post(challenge::send_email_challenge_handler),
        )
        .route(
            "/challenge/email/check",
            post(challenge::check_challenge_handler),
        )
}
