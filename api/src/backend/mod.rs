pub mod auth;
mod challenge;
pub mod environments;
pub mod projects;
mod provider;
pub mod secrets;

pub use auth::{CreateUserRequest, SessionPackage};

pub use challenge::{CheckChallengeResult, PendingChallenge};
pub use provider::BackendProvider;
use secretpass_core::enums::OperationMode;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiStateInner {
    pub mode: OperationMode,
    pub backend: Arc<dyn BackendProvider>,
}

pub type ApiState = Arc<ApiStateInner>;
