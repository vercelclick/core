pub use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

#[macro_export]
macro_rules! source {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        // Trim the trailing "::f" from the type name
        &name[..name.len() - 3]
    }};
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDepth {
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalError {
    pub code: u16,
    pub reason: Option<String>,
    pub message: String,
    pub source: String,
    pub depth: Vec<ErrorDepth>,
}

impl InternalError {
    pub fn trace(source: &str, status_code: StatusCode, message: &str, error: impl Debug) -> Self {
        #[cfg(feature = "trace")]
        {
            tracing::error!("[{source} -> {status_code}] {message}: {:?}", error);
        }
        Self::build(source, status_code, message, vec![])
    }

    pub fn extend(
        source: &str,
        status_code: StatusCode,
        message: &str,
        error: &InternalError,
    ) -> Self {
        let mut depth = error.depth.clone();
        depth.insert(
            0,
            ErrorDepth {
                source: error.source.clone(),
                message: error.message.clone(),
            },
        );
        Self::build(source, status_code, message, depth)
    }

    pub fn new(source: &str, status_code: StatusCode, message: &str) -> Self {
        Self::build(source, status_code, message, vec![])
    }

    fn build(source: &str, status_code: StatusCode, message: &str, depth: Vec<ErrorDepth>) -> Self {
        Self {
            depth,
            code: status_code.as_u16(),
            source: source.to_string(),
            message: message.to_string(),
            reason: status_code
                .canonical_reason()
                .map(|reason| reason.to_string()),
        }
    }
}

impl Display for InternalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Error {} {}<{}>: {}",
            self.source,
            self.reason.clone().unwrap_or("".to_string()),
            self.code,
            self.message
        )
    }
}

impl std::error::Error for InternalError {}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for InternalError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            axum::Json(self),
        )
            .into_response()
    }
}

pub type InternalResult<T> = Result<T, InternalError>;
