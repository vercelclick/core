pub mod auth;
mod challenge;
pub mod projects;
mod provider;

use crate::constants::{CLOUD_RP_CONFIG, LOCAL_RP_CONFIG, PROXY_REQUEST_HEADER, RpConfig};
pub use auth::{CreateUserRequest, SessionPackage};
use axum::http::HeaderMap;
pub use challenge::{CheckChallengeResult, PendingChallenge};
pub use provider::BackendProvider;
use secretpass_core::enums::OperationMode;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub mode: OperationMode,
    pub backend: Arc<dyn BackendProvider>,
}

impl ApiState {
    pub(crate) fn is_proxied(&self, headers: &HeaderMap) -> bool {
        if let Some(is_proxied) = headers.get(PROXY_REQUEST_HEADER)
            && is_proxied == "true"
        {
            true
        } else {
            false
        }
    }

    pub(crate) fn get_rp_config(&self, headers: &HeaderMap) -> &'static RpConfig {
        if self.is_proxied(headers) {
            return &LOCAL_RP_CONFIG;
        }

        if self.mode == OperationMode::Local {
            &LOCAL_RP_CONFIG
        } else {
            &CLOUD_RP_CONFIG
        }
    }
}
