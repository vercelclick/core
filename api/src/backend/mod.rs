pub mod auth;
pub mod environments;
pub mod projects;
mod provider;
pub mod secrets;

pub use provider::BackendProvider;
use std::sync::Arc;

pub type ApiState = Arc<ApiStateInner>;

#[derive(Clone)]
pub struct ApiStateInner {
    pub backend: Arc<dyn BackendProvider>,
}

impl ApiStateInner {
    pub fn new(backend: Arc<dyn BackendProvider>) -> Self {
        Self { backend }
    }
}
