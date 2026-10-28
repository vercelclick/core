use secretpass_core::enums::ContributorRole;
use secretpass_core::{Contributor, ContributorPublicKey, MachinePublicKey};
use std::path::Path;
use std::{fs, io};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct LocalKeysConfig {
    pub contributors_keys: Vec<ContributorPublicKey>,
    pub machines_keys: Vec<MachinePublicKey>,
}

impl LocalKeysConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path).join(".spass");
        if !path.exists() {
            return Ok(Self::default());
        }

        let [contributors_content, machines_content]: [io::Result<String>; 2] =
            ["contributors.json", "machines.json"].map(|file_name| {
                let file_path = path.join(file_name);
                let content = if !file_path.is_file() {
                    "[]".to_string()
                } else {
                    fs::read_to_string(file_path)?
                };
                Ok(content)
            });

        let contributors_keys: Vec<ContributorPublicKey> =
            serde_json::from_str(&contributors_content?)?;
        let machines_keys: Vec<MachinePublicKey> = serde_json::from_str(&machines_content?)?;

        Ok(Self {
            contributors_keys,
            machines_keys,
        })
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass");

        let machines_content = serde_json::to_string_pretty(&self.machines_keys)?;
        let contributors_content = serde_json::to_string_pretty(&self.contributors_keys)?;
        fs::write(path.join("machines.json"), machines_content)?;
        fs::write(path.join("contributors.json"), contributors_content)?;

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
                    || contributor.environments.contains(&env_name.to_string())
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
            .filter(|key| key.environments.contains(&env_name.to_string()))
            .cloned()
            .collect();

        (contributor_keys, machine_keys)
    }
}
