pub mod challenge;

pub mod middleware;

pub mod session;

use crate::backend::ApiState;
use crate::routes::auth::challenge::generate_webauthn_challenge_handler;

use axum::Router;
use axum::routing::post;

pub fn auth_router() -> Router<ApiState> {
    Router::new().route("/challenge", post(generate_webauthn_challenge_handler))
}
