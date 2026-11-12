pub mod create;

use axum::Router;
use axum::routing::post;
use click_api::backend::ApiState;

pub fn user_passkey_routes() -> Router<ApiState> {
    Router::new()
        .route("/create", post(create::passkey_create_handler))
        .route("/create/challenge", post(create::passkey_create_challenge))
}
