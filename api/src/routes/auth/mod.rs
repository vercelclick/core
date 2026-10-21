mod challenge;
mod login;
mod register;

use crate::backend::ApiState;
use crate::routes::auth::register::create_user;
use axum::Router;
use axum::routing::post;
pub use challenge::{GenerateChallengePrams, generate_challenge_handler};

pub fn auth_router() -> Router<ApiState> {
    Router::new()
        .route("/challenge", post(generate_challenge_handler))
        .route("/register", post(create_user))
}
