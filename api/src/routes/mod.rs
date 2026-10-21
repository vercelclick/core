mod auth;
pub mod types;

use crate::ApiState;
use crate::routes::auth::auth_router;
use axum::Router;
use axum::http::{HeaderValue, Method};
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;

const HOST_ORIGIN: &str = env!("UI_ORIGIN");

pub fn create_backend_app() -> Router<ApiState> {
    let allowed_origin = HOST_ORIGIN.parse::<HeaderValue>().unwrap();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        .nest("/api/auth", auth_router())
        .layer(cors)
        .layer(CookieManagerLayer::new())
}
