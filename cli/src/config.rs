use secretpass_api::SessionPackage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;
use uuid::Uuid;

pub static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    dirs::config_local_dir()
        .expect("Unable to infer user config directory")
        .join("spass")
});

pub static HOME_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| dirs::home_dir().expect("Unable to infer home directory"));

pub static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    dirs::data_local_dir()
        .expect("Unable to infer home directory")
        .join("spass")
});

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalServiceConfig {
    pub pending_projects: Vec<String>,
    pub know_projects: Vec<(String, Uuid)>,
    pub sessions: HashMap<String, SessionPackage>,
}

impl LocalServiceConfig {
    pub fn load() -> anyhow::Result<Self> {
        if !CONFIG_DIR.is_dir() {
            fs::create_dir_all(CONFIG_DIR.clone())?;
            return Ok(Default::default());
        }

        let config_file = CONFIG_DIR.join("config.json");
        if !config_file.exists() {
            return Ok(Default::default());
        }

        let content = fs::read_to_string(config_file)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let config_file = CONFIG_DIR.join("config.json");

        let content = serde_json::to_string(self)?;

        fs::write(config_file, content)?;

        Ok(())
    }
}
