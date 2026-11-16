#[cfg(debug_assertions)]
pub const RP_ID: &str = "click.localhost";

#[cfg(not(debug_assertions))]
pub const RP_ID: &str = "vault.vercel.click";

#[cfg(debug_assertions)]
pub const RP_ORIGIN: &str = "http://click.localhost:3001";

#[cfg(not(debug_assertions))]
pub const RP_ORIGIN: &str = "https://vault.vercel.click";

pub const ENVIRONMENT_ALL_ACCESS: &str = "$ALL$";

pub const ACCESS_KEY_LENGTH: usize = 80;
pub const FEDERATED_ACCESS_KEY_LENGTH: usize = 32;

#[cfg(debug_assertions)]
pub const APP_SLUG: &str = "click-dev";

#[cfg(not(debug_assertions))]
pub const APP_SLUG: &str = "click";
