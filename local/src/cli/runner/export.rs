use crate::cli::command::ExportFormat;
use crate::cli::utils::get_safe_value;
use click_core::{InternalError, StatusCode, caller};
use std::collections::HashMap;

pub fn export_secrets(plain_values: HashMap<String, String>, format: ExportFormat) {
    match format {
        ExportFormat::DotEnv => export_env(&plain_values),
        ExportFormat::GithubActions => export_github(&plain_values),
        ExportFormat::Json => {
            let json_content = serde_json::to_string_pretty(&plain_values)
                .map_err(|err| {
                    InternalError::trace(
                        caller!(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error encoding secrets",
                        err,
                    )
                })
                .unwrap();
            println!("{}", json_content)
        }
    }
}

fn export_env(values: &HashMap<String, String>) {
    for (key, value) in values {
        println!("{}={}", key, get_safe_value(value))
    }
}

fn export_github(values: &HashMap<String, String>) {
    for (key, value) in values {
        let safe_value = get_safe_value(value);
        println!(
            "{}={}",
            key,
            safe_value
                .strip_circumfix("\"", "\"")
                .unwrap_or(&safe_value)
        )
    }
}
