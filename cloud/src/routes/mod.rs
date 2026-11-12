use axum::Router;

use click_api::backend::ApiState;

pub mod auth;
mod user;

pub fn public_cloud_routes() -> Router<ApiState> {
    Router::new().nest("/auth", auth::auth_routes())
}

pub fn cloud_routes() -> Router<ApiState> {
    Router::new().nest("/users", user::user_routes())
}
