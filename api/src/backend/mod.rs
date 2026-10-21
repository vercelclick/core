mod auth;
mod challenge;
mod provider;

pub use auth::{CreateUserParams, SessionResponse};
pub use challenge::PendingChallenge;
pub use provider::BackendProvider;
use secretpass_core::enums::OperationMode;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub mode: OperationMode,
    pub backend: Arc<dyn BackendProvider>,
}
