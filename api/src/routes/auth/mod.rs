mod challenge;
mod login;
mod register;
mod session;
mod shared;

use crate::backend::ApiState;
use crate::routes::auth::challenge::check_challenge_handler;
use crate::routes::auth::login::{login_user_with_email, login_user_with_passkey};
use crate::routes::auth::register::create_user;
use crate::routes::auth::session::get_session_handler;
use axum::Router;
use axum::routing::{get, post};
pub use challenge::{GenerateChallengeRequest, generate_challenge_handler};

pub fn auth_router() -> Router<ApiState> {
    Router::new()
        .route("/register", post(create_user))
        .route("/login/email", post(login_user_with_email))
        .route("/login/passkey", post(login_user_with_passkey))
        .route("/challenge", post(generate_challenge_handler))
        .route("/challenge/check", post(check_challenge_handler))
        .route("/session", get(get_session_handler))
}
