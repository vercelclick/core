use secretpass_core::{Contributor, Environment, Project, User};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProjectConfig {
    pub project: Project,
    pub environments: Vec<Environment>,
    pub contributors: Vec<(User, Contributor)>,
}

impl LocalProjectConfig {
    pub fn load(path: &str) -> anyhow::Result<Option<Self>> {
        let path = Path::new(path).join(".spass").join("config.json");

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;

        Ok(Some(config))
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass");

        if !path.exists() {
            fs::create_dir_all(path.clone())?;
        }

        let content = serde_json::to_string_pretty(self)?;
        let config_file = path.join("config.json");

        fs::write(config_file, content)?;

        Ok(())
    }

    pub fn get_contributor_by_user_id(&self, user_id: Uuid) -> Option<Contributor> {
        for (user, contributor) in self.contributors.iter() {
            if user.id == user_id && contributor.user_id == user_id {
                return Some(contributor.clone());
            }
        }
        None
    }

    pub fn get_environment(&self, name: &str) -> Option<Environment> {
        for env in self.environments.iter() {
            if env.name == name {
                return Some(env.clone());
            }
        }
        None
    }

    pub fn get_contributors(&self) -> Vec<Contributor> {
        self.contributors
            .iter()
            .map(|(_, user)| user.clone())
            .collect()
    }
}
