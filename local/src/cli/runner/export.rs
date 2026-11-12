use crate::cli::command::ExportFormat;
use click_core::{InternalError, KeyPair, StatusCode, caller};
use std::collections::HashMap;

pub fn export_secrets(
    private_key: KeyPair,
    encrypted_secrets: HashMap<String, String>,
    format: ExportFormat,
) {
    let plain_values = private_key.decrypt_package(&encrypted_secrets).unwrap();

    match format {
        ExportFormat::DotEnv => export_env(plain_values),
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

fn export_env(values: HashMap<String, String>) {
    for (key, value) in values {
        println!("{}={}", key, value)
    }
}
