use secretpass_core::{MachinePublicKey, ProjectUserPasskey};
use std::path::Path;
use std::{fs, io};

#[derive(Debug, Default)]
pub struct LocalKeysConfig {
    pub passkeys: Vec<ProjectUserPasskey>,
    pub machines: Vec<MachinePublicKey>,
}

impl LocalKeysConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path).join(".spass");
        if !path.is_dir() {
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
}
