use axum::http::StatusCode;

pub type HttpError = (StatusCode, String);
pub type HttpResponse<B> = Result<B, HttpError>;
