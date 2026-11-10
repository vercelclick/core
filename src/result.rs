pub use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

macro_rules! resolve_caller {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        // Trim the trailing "::{{closure}}::{{closure}}::f" from the type name
        &name[..name.len() - 29]
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
    pub fn trace(status_code: StatusCode, message: &str, _error: impl Debug) -> Self {
        let source = resolve_caller!();
        let source = source.strip_prefix("::trace").unwrap_or(source);
        #[cfg(feature = "trace")]
        {
            tracing::error!("{} [{status_code}] {message}\n\t{:?}", source, _error);
        }
        Self::build(source.to_string(), status_code, message, vec![])
    }

    pub fn extend(status_code: StatusCode, message: &str, error: &InternalError) -> Self {
        let source = resolve_caller!();
        let source = source.strip_prefix("::extend").unwrap_or(source);

        let mut depth = error.depth.clone();
        depth.insert(
            0,
            ErrorDepth {
                source: error.source.clone(),
                message: error.message.clone(),
            },
        );
        Self::build(source.to_string(), status_code, message, depth)
    }

    pub fn new(status_code: StatusCode, message: &str) -> Self {
        let source = resolve_caller!();
        let source = source.strip_prefix("::new").unwrap_or(source);

        Self::build(source.to_string(), status_code, message, vec![])
    }

    fn build(
        source: String,
        status_code: StatusCode,
        message: &str,
        depth: Vec<ErrorDepth>,
    ) -> Self {
        Self {
            depth,
            source,
            code: status_code.as_u16(),
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
