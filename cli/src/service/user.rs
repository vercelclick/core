use secretpass_core::{SecretpassProjectUser, SecretpassProjectUserPublicKey, SecretpassUser};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalUserConfig {
    pub user: SecretpassUser,
    pub project_user: SecretpassProjectUser,
    pub public_keys: Vec<SecretpassProjectUserPublicKey>,
}

impl LocalUserConfig {
    pub fn load(path: &str, user_id: Uuid) -> anyhow::Result<Option<Self>> {
        let path = Path::new(path).join(".spass").join("users");
        if !path.is_dir() {
            return Ok(None);
        }

        let config_file = path.join(format!("{user_id}.json"));
        if !config_file.is_file() {
            return Ok(None);
        }

        let content = fs::read_to_string(config_file)?;
        let config: Self = serde_json::from_str(&content)?;

        Ok(Some(config))
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass").join("users");
        if !path.is_dir() {
            fs::create_dir_all(path.clone())?;
        }

        let config_file = path.join(format!("{}.json", self.user.id));

        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_file, content)?;

        Ok(())
    }
}
