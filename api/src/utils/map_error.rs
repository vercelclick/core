use crate::routes::types::HttpError;
use axum::http::StatusCode;

pub fn error_mapper(status: StatusCode, title: &str) -> impl Fn(anyhow::Error) -> HttpError {
    let title = title.to_string();
    move |error: anyhow::Error| -> HttpError {
        tracing::error!("{title}: {:?}", error);

        (status, format!("{}: {}", title, error))
    }
}
