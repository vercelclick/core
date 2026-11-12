pub const RP_ID: &str = env!("RP_ID");
pub const RP_ORIGIN: &str = env!("RP_ORIGIN");
pub const API_HOST_DOMAIN: &str = "api.secretpass.cloud";
pub const ENVIRONMENT_ALL_ACCESS: &str = "$ALL$";

pub const ACCESS_KEY_LENGTH: usize = 80;
pub const FEDERATED_ACCESS_KEY_LENGTH: usize = 32;

#[cfg(debug_assertions)]
pub const APP_SLUG: &str = "click-dev";

#[cfg(not(debug_assertions))]
pub const APP_SLUG: &str = "click";
