pub mod challenge;
mod login;
pub mod middleware;
pub mod register;
pub mod session;
mod shared;

use crate::backend::ApiState;
use crate::routes::auth::challenge::check_challenge_handler;
use crate::routes::auth::login::{login_user_with_email, login_user_with_passkey, start_login};
use crate::routes::auth::middleware::AuthLayer;
use crate::routes::auth::register::create_user;
use crate::routes::auth::session::{get_session_handler, logout_handler};
use axum::Router;
use axum::routing::{get, post};
pub use challenge::{GenerateChallengeRequest, generate_challenge_handler};

pub fn auth_router(auth_layer: AuthLayer) -> Router<ApiState> {
    Router::new()
        .route("/session", get(get_session_handler).delete(logout_handler))
        .layer(auth_layer)
        .route("/register", post(create_user))
        .route("/login/start", post(start_login))
        .route("/login/email", post(login_user_with_email))
        .route("/login/passkey", post(login_user_with_passkey))
        .route("/challenge", post(generate_challenge_handler))
        .route("/challenge/check", post(check_challenge_handler))
}
