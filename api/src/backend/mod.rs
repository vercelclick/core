pub mod auth;
mod challenge;
pub mod environments;
pub mod projects;
mod provider;
pub mod secrets;

pub use challenge::PendingChallenge;
pub use provider::BackendProvider;
use secretpass_core::enums::OperationMode;
use std::sync::Arc;

pub type ApiState = Arc<ApiStateInner>;

#[derive(Clone)]
pub struct ApiStateInner {
    pub mode: OperationMode,
    pub backend: Arc<dyn BackendProvider>,
}

#[cfg(feature = "cloud")]
impl ApiStateInner {
    pub fn new(backend: Arc<dyn BackendProvider>) -> Self {
        Self {
            mode: OperationMode::Cloud,
            backend,
        }
    }
}

#[cfg(not(feature = "cloud"))]
impl ApiStateInner {
    pub fn new(backend: Arc<dyn BackendProvider>) -> Self {
        Self {
            mode: OperationMode::Local,
            backend,
        }
    }
}
