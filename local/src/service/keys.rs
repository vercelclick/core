use secretpass_core::enums::ContributorRole;
use secretpass_core::{
    Contributor, ContributorPublicKey, InternalError, InternalResult, MachinePublicKey, StatusCode,
    source,
};
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct LocalKeysConfig {
    pub contributors_keys: Vec<ContributorPublicKey>,
    pub machines_keys: Vec<MachinePublicKey>,
}

impl LocalKeysConfig {
    pub fn load(path: &str) -> InternalResult<Self> {
        let path = Path::new(path).join(".spass");
        if !path.exists() {
            return Ok(Self::default());
        }

        let [contributors_content, machines_content]: [InternalResult<String>; 2] =
            ["contributors.json", "machines.json"].map(|file_name| {
                let file_path = path.join(file_name);
                let content = if !file_path.is_file() {
                    "[]".to_string()
                } else {
                    fs::read_to_string(file_path.clone()).map_err(|err| {
                        InternalError::trace(
                            source!(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Error reading keys config {}", file_path.display()),
                            err,
                        )
                    })?
                };
                Ok(content)
            });

        let contributors_keys: Vec<ContributorPublicKey> =
            serde_json::from_str(&contributors_content?).map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "Error deserializing contributors keys config {}",
                        path.join("contributors.json").display()
                    ),
                    err,
                )
            })?;
        let machines_keys: Vec<MachinePublicKey> = serde_json::from_str(&machines_content?)
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "Error deserializing access keys config {}",
                        path.join("machines.json").display()
                    ),
                    err,
                )
            })?;

        Ok(Self {
            contributors_keys,
            machines_keys,
        })
    }

    pub fn write(&self, path: &str) -> InternalResult<()> {
        let path = Path::new(path).join(".spass");

        let machines_content =
            serde_json::to_string_pretty(&self.machines_keys).map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "Error serializing access keys config {}",
                        path.join("machines.json").display()
                    ),
                    err,
                )
            })?;
        let contributors_content =
            serde_json::to_string_pretty(&self.contributors_keys).map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "Error serializing contributors keys config {}",
                        path.join("contributors.json").display()
                    ),
                    err,
                )
            })?;

        fs::write(path.join("machines.json"), machines_content).map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error writing access keys config {}",
                    path.join("machines.json").display()
                ),
                err,
            )
        })?;

        fs::write(path.join("contributors.json"), contributors_content).map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "Error writing contributors keys config {}",
                    path.join("contributors.json").display()
                ),
                err,
            )
        })?;

        Ok(())
    }

    pub fn get_contributor_keys(&self, contributor_id: Uuid) -> Vec<ContributorPublicKey> {
        self.contributors_keys
            .iter()
            .filter(|pk| pk.contributor_id == contributor_id)
            .cloned()
            .collect()
    }

    pub fn get_environment_public_keys(
        &self,
        env_name: &str,
        contributors: &[Contributor],
    ) -> (Vec<ContributorPublicKey>, Vec<MachinePublicKey>) {
        let contributor_ids: Vec<Uuid> = contributors
            .iter()
            .filter_map(|contributor| {
                if contributor.role == ContributorRole::Admin
                    || contributor.get_access(env_name).is_some()
                {
                    Some(contributor.id)
                } else {
                    None
                }
            })
            .collect();
        let contributor_keys = self
            .contributors_keys
            .iter()
            .filter(|pk| contributor_ids.contains(&pk.contributor_id))
            .cloned()
            .collect();

        let machine_keys = self
            .machines_keys
            .iter()
            .filter(|key| key.get_access(env_name).is_some())
            .cloned()
            .collect();

        (contributor_keys, machine_keys)
    }
}
