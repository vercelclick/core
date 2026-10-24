use secretpass_core::{SecretpassEnvironment, SecretpassProject};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProjectConfig {
    pub project: SecretpassProject,
    pub environments: Vec<SecretpassEnvironment>,
}

impl LocalProjectConfig {
    pub fn load(path: &str) -> anyhow::Result<Option<Self>> {
        let path = Path::new(path).join(".spass");
        if !path.is_dir() {
            return Ok(None);
        }

        let config_file = path.join("config.json");
        if !path.is_file() {
            return Ok(None);
        }

        let content = fs::read_to_string(config_file)?;
        let config: Self = serde_json::from_str(&content)?;

        Ok(Some(config))
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass");

        if !path.exists() {
            fs::create_dir_all(path.clone())?;
        }

        let content = serde_json::to_string_pretty(&self.project)?;
        let config_file = path.join("config.json");

        fs::write(config_file, content)?;

        Ok(())
    }
}
