use secretpass_core::OperationMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub analytics: Option<AnalyticsConfig>,
    pub mode: OperationMode,
}

// We use posthog for analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub token: String,
    pub ui_host: String,
    pub api_host: String,
}
