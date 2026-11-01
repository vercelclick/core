use crate::cli::command::ExportFormat;
use secretpass_core::PrivateKey;
use std::collections::HashMap;

pub fn export_secrets(
    private_key: PrivateKey,
    encrypted_secrets: HashMap<String, String>,
    format: ExportFormat,
) {
    let plain_values = private_key
        .decrypt_package(&encrypted_secrets)
        .map_err(|err| anyhow::format_err!("Error decrypting secrets: {:?}", err))
        .unwrap();

    match format {
        ExportFormat::DotEnv => export_env(plain_values),
        ExportFormat::Json => {
            let json_content = serde_json::to_string_pretty(&plain_values)
                .map_err(|err| anyhow::format_err!("Error encoding secrets: {:?}", err))
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
