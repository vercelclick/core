pub mod passkeys;

use crate::routes::user::passkeys::user_passkey_routes;
use axum::Router;
use click_api::backend::ApiState;

pub fn user_routes() -> Router<ApiState> {
    Router::new().nest("/passkeys", user_passkey_routes())
}
