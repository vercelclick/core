use secretpass_core::{
    Contributor, Environment, InternalError, InternalResult, Project, StatusCode, User,
};
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
    pub fn load(path: &str) -> InternalResult<Option<Self>> {
        let path = Path::new(path).join(".spass").join("config.json");

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(path.clone()).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error reading project config {}", path.display()),
                err,
            )
        })?;
        let config: Self = serde_json::from_str(&content).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error deserializing project config {}", path.display()),
                err,
            )
        })?;

        Ok(Some(config))
    }

    pub fn write(&self, path: &str) -> InternalResult<()> {
        let path = Path::new(path).join(".spass");

        if !path.exists() {
            fs::create_dir_all(path.clone()).map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Error creating project directory {}", path.display()),
                    err,
                )
            })?;
        }

        let config_file = path.join("config.json");
        let content = serde_json::to_string_pretty(self).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error serializing project config {}", config_file.display()),
                err,
            )
        })?;

        fs::write(config_file.clone(), content).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error writing project config {}", path.display()),
                err,
            )
        })?;

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
