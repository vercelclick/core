mod auth;
pub mod types;

use crate::ApiState;
use crate::routes::auth::auth_router;
use axum::Router;
use secretpass_core::OperationMode;

pub fn create_backend_app(mode: OperationMode) -> Router<ApiState> {
    let prefix = format!("/api/{}", mode).to_ascii_lowercase();
    Router::new().nest(&prefix, auth_router())
}
