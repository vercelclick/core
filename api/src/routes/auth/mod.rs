mod challenge;

use crate::backend::ApiState;
use axum::Router;
use axum::routing::post;
pub use challenge::{GenerateChallengePrams, generate_challenge_handler};

pub fn auth_router() -> Router<ApiState> {
    Router::new().route("/auth/challenge", post(generate_challenge_handler))
}
