use secretpass_api::environments::SecretWithEncryptedValues;
use secretpass_core::{
    MachineSecretValue, PasskeySecretValue, ProjectUserPasskey, SecretDefinition,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

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

    pub fn load_env(path: &str, env_name: &str) -> anyhow::Result<Vec<Self>> {
        let env_path = Path::new(path)
            .join(".spass")
            .join("secrets")
            .join(env_name);
        if !env_path.exists() {
            return Ok(vec![]);
        }

        let entries = fs::read_dir(env_path)?;

        let mut configs: Vec<Self> = Vec::new();

        for entry in entries.into_iter() {
            let entry = entry?;
            let file_path = entry.path();
            let file_name = match file_path.file_name() {
                Some(name) => name,
                None => continue,
            };

            let file_name = format!("{}", file_name.display());
            let secret_name = match file_name.strip_suffix(".json") {
                Some(name) => name,
                None => continue,
            };

            if let Some(config) = Self::load(path, env_name, secret_name)? {
                configs.push(config)
            };
        }

        Ok(configs)
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

    pub fn build_values_for_user(
        &self,
        passkeys: &[ProjectUserPasskey],
    ) -> SecretWithEncryptedValues {
        let valid_ids: Vec<Uuid> = passkeys.iter().map(|key| key.id).collect();
        let passkey_values = self
            .passkey_values
            .iter()
            .filter(|value| valid_ids.contains(&value.passkey_id))
            .cloned()
            .collect();

        SecretWithEncryptedValues {
            definition: self.definition.clone(),
            passkey_values,
        }
    }
}
