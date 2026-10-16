use crate::routes::types::HttpError;
use axum::http::StatusCode;

pub fn error_mapper(status: StatusCode, title: &str) -> impl Fn(anyhow::Error) -> HttpError {
    let title = title.to_string();
    let mapper = move |error: anyhow::Error| -> HttpError {
        (status.clone(), format!("{}: {}", title, error))
    };

    mapper
}
