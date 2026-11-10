pub mod passkeys;

use crate::backend::ApiState;
use crate::routes::user::passkeys::user_passkey_routes;
use axum::Router;

pub fn user_routes() -> Router<ApiState> {
    Router::new().nest("/passkeys", user_passkey_routes())
}
