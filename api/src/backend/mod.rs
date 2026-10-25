pub mod auth;
mod challenge;
pub mod projects;
mod provider;

use crate::constants::{CLOUD_RP_CONFIG, LOCAL_RP_CONFIG, RpConfig};
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

impl ApiStateInner {
    pub(crate) fn get_rp_config(&self, is_proxied: bool) -> &'static RpConfig {
        if self.mode == OperationMode::Local || is_proxied {
            &LOCAL_RP_CONFIG
        } else {
            &CLOUD_RP_CONFIG
        }
    }
}

pub type ApiState = Arc<ApiStateInner>;
