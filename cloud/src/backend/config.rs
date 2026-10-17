use secretpass_api::BackendConfig;
use secretpass_core::OperationMode;

pub static CLOUD_CONFIG: BackendConfig = BackendConfig {
    analytics: None,
    mode: OperationMode::Cloud,
};
