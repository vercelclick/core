use click_api::backend::environments::SecretWithEncryptedValues;
use click_core::constants::APP_SLUG;
use click_core::{
    ContributorPublicKey, InternalError, InternalResult, SecretDefinition, SecretValue, StatusCode,
    caller,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSecretConfig {
    pub definition: SecretDefinition,
    pub values: Vec<SecretValue>,
}

impl LocalSecretConfig {
    pub fn load(path: &str, env_name: &str, secret_name: &str) -> InternalResult<Option<Self>> {
        let path = Path::new(path)
            .join(format!(".{}", APP_SLUG))
            .join("secrets")
            .join(env_name);
        if !path.exists() {
            return Ok(None);
        }

        let config_file = path.join(format!("{secret_name}.json"));
        if !config_file.is_file() {
            return Ok(None);
        }

        let content = fs::read_to_string(config_file.clone()).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error reading secret config {}", config_file.display()),
                err,
            )
        })?;

        let config: Self = serde_json::from_str(&content).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error deserializing secret config {}",
                    config_file.display()
                ),
                err,
            )
        })?;

        Ok(Some(config))
    }

    pub fn load_env(path: &str, env_name: &str) -> InternalResult<Vec<Self>> {
        let env_path = Path::new(path)
            .join(format!(".{}", APP_SLUG))
            .join("secrets")
            .join(env_name);
        if !env_path.exists() {
            return Ok(vec![]);
        }

        let entries = fs::read_dir(env_path.clone()).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error reading environment directory {}", env_path.display()),
                err,
            )
        })?;

        let mut configs: Vec<Self> = Vec::new();

        for entry in entries.into_iter() {
            let entry = entry.map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Error processing secret entry from {}", env_path.display()),
                    err,
                )
            })?;

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

    pub fn write(&self, path: &str) -> InternalResult<()> {
        let path = Path::new(path)
            .join(format!(".{}", APP_SLUG))
            .join("secrets")
            .join(&self.definition.env_name);

        if !path.exists() {
            fs::create_dir_all(path.clone()).map_err(|err| {
                InternalError::trace(
                    caller!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error establishing a transaction",
                    err,
                )
            })?;
        }

        let config_file = path.join(format!("{}.json", self.definition.name));

        let content = serde_json::to_string_pretty(self).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error serializing secret config {}", config_file.display()),
                err,
            )
        })?;
        fs::write(config_file.clone(), content).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error writing secret config {}", config_file.display()),
                err,
            )
        })?;

        Ok(())
    }

    pub fn build_values_for_contributors(
        &self,
        public_keys: &[ContributorPublicKey],
    ) -> SecretWithEncryptedValues {
        SecretWithEncryptedValues::extract(&self.definition, public_keys, &self.values)
    }
}
