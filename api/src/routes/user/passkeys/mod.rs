pub mod create;

use crate::ApiState;
use crate::routes::user::passkeys::create::{
    create_passkey_complete_handler, create_passkey_start_handler,
};
use axum::Router;
use axum::routing::post;

pub fn user_passkey_routes() -> Router<ApiState> {
    Router::new()
        .route("/create/start", post(create_passkey_start_handler))
        .route("/create", post(create_passkey_complete_handler))
}
