use axum::Router;
use axum::routing::post;
use click_api::backend::ApiState;

mod challenge;
mod signin;
pub mod signup;

pub fn auth_routes() -> Router<ApiState> {
    Router::new()
        .route("/signup", post(signup::signup_handler))
        .route("/signup/challenge", post(signup::signup_passkey_challenge))
        .route("/signin/email", post(signin::signin_with_email))
        .route("/signin/passkey", post(signin::signin_with_passkey))
        .route(
            "/signin/passkey/challenge",
            post(signin::signin_with_passkey_challenge),
        )
        .route(
            "/challenge/email",
            post(challenge::send_email_challenge_handler),
        )
        .route(
            "/challenge/email/check",
            post(challenge::check_challenge_handler),
        )
}
