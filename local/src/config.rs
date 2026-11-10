use crate::service::project::LocalProjectConfig;
use secretpass_api::backend::SessionPackage;
use secretpass_core::{Contributor, InternalError, InternalResult, StatusCode};
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
    pub fn load() -> InternalResult<Self> {
        if !CONFIG_DIR.exists() {
            fs::create_dir_all(CONFIG_DIR.clone()).map_err(|err| {
                InternalError::trace(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "Error creating local service config directory {}",
                        CONFIG_DIR.display()
                    ),
                    err,
                )
            })?;
            return Ok(Default::default());
        }

        let config_file = CONFIG_DIR.join("config.json");
        if !config_file.exists() {
            return Ok(Default::default());
        }

        let content = fs::read_to_string(config_file.clone()).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error reading local service config {}",
                    config_file.display()
                ),
                err,
            )
        })?;
        // Overwrite the config if there's an issue with the current config
        let config: Self = serde_json::from_str(&content).unwrap_or(Default::default());
        Ok(config)
    }

    pub fn write(&self) -> InternalResult<()> {
        let config_file = CONFIG_DIR.join("config.json");

        let content = serde_json::to_string(self).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error serializing local service config {}",
                    config_file.display()
                ),
                err,
            )
        })?;

        fs::write(config_file.clone(), content).map_err(|err| {
            InternalError::trace(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error writing local service config {}",
                    config_file.display()
                ),
                err,
            )
        })?;

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

    pub fn get_project_by_id(
        &self,
        project_id: Uuid,
    ) -> InternalResult<Option<(String, LocalProjectConfig)>> {
        for (path, id) in self.attached_projects.iter() {
            if project_id == *id {
                let project_config =
                    LocalProjectConfig::load(path)?.map(|config| (path.clone(), config));
                return Ok(project_config);
            }
        }

        Ok(None)
    }

    pub fn get_project_and_contributor(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> InternalResult<(String, LocalProjectConfig, Contributor)> {
        let (path, project_conf) = self.get_project_by_id(project_id)?.ok_or_else(|| {
            InternalError::new(
                StatusCode::NOT_FOUND,
                "Project not found, confirm if the project is attached",
            )
        })?;

        let contributor = project_conf
            .get_contributor_by_user_id(user_id)
            .ok_or_else(|| {
                InternalError::new(
                    StatusCode::FORBIDDEN,
                    "You don't have access to this project under the current user",
                )
            })?;
        Ok((path, project_conf, contributor))
    }
}
