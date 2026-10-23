use crate::api_types::HttpResponse;
use crate::constants::{CLOUD_PROXY_BASE_URL, PROXY_REQUEST_HEADER};
use axum::http::{Method, StatusCode, Uri};
use reqwest::{Client, RequestBuilder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::LazyLock;

static REQWEST_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

#[derive(Debug)]
pub(crate) struct CloudProxy {
    builder: RequestBuilder,
}

impl CloudProxy {
    pub fn new(method: Method, uri: Uri) -> Self {
        let path = uri.path();
        Self {
            builder: REQWEST_CLIENT
                .request(method, format!("{}{}", CLOUD_PROXY_BASE_URL, path))
                .header(PROXY_REQUEST_HEADER, "true"),
        }
    }

    pub fn json<T: Serialize>(self, json: &T) -> Self {
        Self {
            builder: self.builder.json(json),
        }
    }

    pub async fn proxy<T>(self) -> HttpResponse<T>
    where
        T: DeserializeOwned,
    {
        let response = self.builder.send().await.map_err(|err| {
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
}
