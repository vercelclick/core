use secretpass_core::SecretpassProjectMachinePublicKey;
use std::fs;
use std::path::Path;

pub struct LocalMachineConfig {
    machines: Vec<SecretpassProjectMachinePublicKey>,
}

impl LocalMachineConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path).join(".spass");
        if !path.is_dir() {
            return Ok(Self { machines: vec![] });
        }

        let config_file = path.join("machines.json");
        if !config_file.is_file() {
            return Ok(Self { machines: vec![] });
        }

        let content = fs::read_to_string(config_file)?;
        let machines: Vec<SecretpassProjectMachinePublicKey> = serde_json::from_str(&content)?;

        Ok(Self { machines })
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let path = Path::new(path).join(".spass");
        if !path.is_dir() {
            fs::create_dir_all(path.clone())?;
        }

        let config_file = path.join("machines.json");

        let content = serde_json::to_string_pretty(&self.machines)?;
        fs::write(config_file, content)?;

        Ok(())
    }
}
