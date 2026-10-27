use secretpass_core::{MachineSecretValue, PasskeySecretValue, SecretDefinition};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSecretConfig {
    pub definition: SecretDefinition,
    pub passkey_values: Vec<PasskeySecretValue>,
    pub machine_values: Vec<MachineSecretValue>,
}

impl LocalSecretConfig {
    pub fn load(path: &str, env_name: &str, secret_name: &str) -> anyhow::Result<Option<Self>> {
        let path = Path::new(path)
            .join(".spass")
            .join("secrets")
            .join(env_name);
        if !path.exists() {
            return Ok(None);
        }

        let config_file = path.join(format!("{secret_name}.json"));
        if !config_file.is_file() {
            return Ok(None);
        }

        let content = fs::read_to_string(config_file)?;
        let config: Self = serde_json::from_str(&content)?;

        Ok(Some(config))
    }

    pub fn write(&self, path: &str, env_name: &str) -> anyhow::Result<()> {
        let path = Path::new(path)
            .join(".spass")
            .join("secrets")
            .join(env_name);

        if !path.exists() {
            fs::create_dir_all(path.clone())?;
        }

        let config_file = path.join(format!("{}.json", self.definition.name));

        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_file, content)?;

        Ok(())
    }
}
