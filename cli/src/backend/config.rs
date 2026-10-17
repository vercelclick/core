use std::sync::LazyLock;

use secretpass_api::AnalyticsConfig;

pub static ANALYTICS_CONFIG: LazyLock<AnalyticsConfig> = LazyLock::new(|| AnalyticsConfig {
    token: env!("POSTHOG_PROJECT_TOKEN").to_string(),
    ui_host: env!("POSTHOG_UI_HOST").to_string(),
    api_host: env!("POSTHOG_API_HOST").to_string(),
});
