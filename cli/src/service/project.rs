use secretpass_core::{SpassEnvironment, SpassProject, SpassProjectUser, SpassUser};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProjectConfig {
    pub project: SpassProject,
    pub environments: Vec<SpassEnvironment>,
    pub users: Vec<(SpassUser, SpassProjectUser)>,
    pub machines: Vec<()>,
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

    pub fn user_has_access(&self, user_id: Uuid) -> bool {
        for (user, project_user) in self.users.iter() {
            if user.id == user_id && project_user.user_id == user_id {
                return true;
            }
        }

        false
    }
}
