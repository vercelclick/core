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
    pub known_projects: Vec<String>,
    pub attached_projects: Vec<(String, Uuid)>,
    pub sessions: HashMap<Uuid, SessionPackage>,
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
        // Overwrite the config if there's an issue with the current config
        let config: Self = serde_json::from_str(&content).unwrap_or(Default::default());
        Ok(config)
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let config_file = CONFIG_DIR.join("config.json");

        let content = serde_json::to_string(self)?;

        fs::write(config_file, content)?;

        Ok(())
    }

    pub fn attach(&mut self, project_path: &String, project_id: Uuid) -> bool {
        for attached in self.attached_projects.iter_mut() {
            if *project_path == attached.0.clone() {
                if attached.1 == project_id {
                    return false;
                }
                attached.1 = project_id;
                return true;
            }
        }

        self.attached_projects
            .push((project_path.clone(), project_id));

        true
    }
}
