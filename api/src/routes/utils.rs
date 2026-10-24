use axum::http::StatusCode;

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
