use secretpass_core::{MachinePublicKey, ProjectUserLevel, ProjectUserPasskey, SpassProjectUser};
use std::path::Path;
use std::{fs, io};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct LocalKeysConfig {
    pub passkeys: Vec<ProjectUserPasskey>,
    pub machines: Vec<MachinePublicKey>,
}

impl LocalKeysConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path).join(".spass");
        if !path.exists() {
            return Ok(Self::default());
        }

        let [passkeys_content, machines_content]: [io::Result<String>; 2] =
            ["passkeys.json", "machines.json"].map(|file_name| {
                let file_path = path.join(file_name);
                let content = if !file_path.is_file() {
                    "[]".to_string()
                } else {
                    fs::read_to_string(file_path)?
                };
                Ok(content)
            });

        let passkeys: Vec<ProjectUserPasskey> = serde_json::from_str(&passkeys_content?)?;
        let machines: Vec<MachinePublicKey> = serde_json::from_str(&machines_content?)?;

        Ok(Self { passkeys, machines })
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass");

        let machines_content = serde_json::to_string_pretty(&self.machines)?;
        let passkeys_content = serde_json::to_string_pretty(&self.passkeys)?;
        fs::write(path.join("machines.json"), machines_content)?;
        fs::write(path.join("passkeys.json"), passkeys_content)?;

        Ok(())
    }

    pub fn get_user_keys(&self, user_id: Uuid) -> Vec<ProjectUserPasskey> {
        self.passkeys
            .iter()
            .filter(|pk| pk.user_id == user_id)
            .cloned()
            .collect()
    }

    pub fn get_environment_machine_keys(
        &self,
        env_name: &str,
        users: &[SpassProjectUser],
    ) -> (Vec<ProjectUserPasskey>, Vec<MachinePublicKey>) {
        let user_ids: Vec<Uuid> = users
            .iter()
            .filter_map(|user| {
                if user.level == ProjectUserLevel::Admin
                    || user.environments.contains(&env_name.to_string())
                {
                    Some(user.id)
                } else {
                    None
                }
            })
            .collect();
        let passkeys = self
            .passkeys
            .iter()
            .filter(|pk| user_ids.contains(&pk.user_id))
            .cloned()
            .collect();

        let machines = self
            .machines
            .iter()
            .filter(|key| key.environments.contains(&env_name.to_string()))
            .cloned()
            .collect();

        (passkeys, machines)
    }
}
