use crate::api_types::HttpResponse;
use axum::http::StatusCode;
use reqwest::{Error, Response};
use serde::de::DeserializeOwned;

const BASE_PROXY_URL: &str = env!("CLOUD_API_URL");

pub(crate) fn cloud_proxy_url(path: &str) -> String {
    format!("{}{}", BASE_PROXY_URL, path)
}

pub(crate) async fn parse_proxied_response<T>(result: Result<Response, Error>) -> HttpResponse<T>
where
    T: DeserializeOwned,
{
    let response = result.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!(
                "Error proxying request to cloud backend: {}",
                err.to_string()
            ),
        )
    })?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error parsing cloud error({}): {}", status, err.to_string()),
            )
        })?;
        return Err((status, text));
    }

    let payload: T = response.json().await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error parsing cloud response: {}", err.to_string()),
        )
    })?;

    Ok(payload)
}
