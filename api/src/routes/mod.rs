mod auth;
pub mod types;

use crate::ApiState;
use crate::routes::auth::auth_router;
use axum::Router;

pub fn create_backend_app() -> Router<ApiState> {
    Router::new().merge(auth_router())
}
