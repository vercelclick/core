use secretpass_core::enums::PasskeyType;

#[derive(Clone)]
pub struct RpConfig {
    pub id: &'static str,
    pub origin: &'static str,
    pub passkey_type: PasskeyType,
}

pub static CLOUD_RP_CONFIG: RpConfig = RpConfig {
    id: env!("CLOUD_RP_ID"),
    origin: env!("CLOUD_RP_ORIGIN"),
    passkey_type: PasskeyType::Cloud,
};

pub static LOCAL_RP_CONFIG: RpConfig = RpConfig {
    id: env!("LOCAL_RP_ID"),
    origin: env!("LOCAL_RP_ORIGIN"),
    passkey_type: PasskeyType::Local,
};

pub const CLOUD_PROXY_BASE_URL: &str = env!("CLOUD_PROXY_URL");

pub const PROXY_REQUEST_HEADER: &str = "Local-Proxy";
pub const SESSION_COOKIE_NAME: &str = "session_token";
