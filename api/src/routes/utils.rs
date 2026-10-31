use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use std::sync::LazyLock;

#[axum::debug_handler]
pub async fn health_endpoint() -> Result<String, (StatusCode, String)> {
    Ok("Ok".to_string())
}

#[axum::debug_handler]
pub async fn ping_endpoint(body: String) -> Result<String, (StatusCode, String)> {
    if body.to_lowercase() != "ping" {
        Err((StatusCode::BAD_REQUEST, "Ping should be ping".to_string()))
    } else {
        Ok("Pong".to_string())
    }
}

static API_VERSION: LazyLock<HeaderValue> =
    LazyLock::new(|| HeaderValue::from_str(env!("CARGO_PKG_VERSION")).unwrap());

pub async fn add_version_header(req: Request, next: Next) -> impl IntoResponse {
    let mut response = next.run(req).await;

    response
        .headers_mut()
        .insert("X-Version", API_VERSION.clone());

    response
}
