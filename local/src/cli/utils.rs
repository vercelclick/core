use std::collections::HashMap;
use std::env;

pub fn get_safe_value(value: &str) -> String {
    serde_json::to_string(value).unwrap_or(value.to_string())
}

pub fn mask_if_github_actions(values: &HashMap<String, String>) {
    let actions_env = match env::var("GITHUB_ACTIONS") {
        Ok(val) => val,
        Err(_) => return,
    };

    if actions_env != "true" {
        return;
    }

    eprintln!("::notice title=Click Vault::Github actions detected, masking secrets");

    for value in values.values() {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let lines = value.split("\n").collect::<Vec<&str>>();

        // Mask the secret as a safe env value
        let safe_value = &get_safe_value(value);
        eprintln!(
            "::add-mask::{}",
            safe_value.strip_circumfix("\"", "\"").unwrap_or(safe_value)
        );

        // Mask for the secret line by line
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            eprintln!("::add-mask::{}", line)
        }
    }
}
