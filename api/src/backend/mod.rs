mod challenge;
mod provider;

pub use challenge::PendingChallenge;
pub use provider::BackendProvider;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub backend: Arc<dyn BackendProvider>,
}
