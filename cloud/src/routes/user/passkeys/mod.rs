pub mod create;
pub mod utils;

use axum::Router;
use secretpass_api::backend::ApiState;

pub fn user_passkey_routes() -> Router<ApiState> {
    Router::new().route(
        "/create",
        axum::routing::post(create::create_passkey_handler),
    )
}
