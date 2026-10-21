use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyFlags {
    pub user_present: bool,
    pub user_verified: bool,
    pub attested_data: bool, // Only available during registration
    pub extension_data: bool,
    pub backup_eligible: bool,
    pub backup_completed: bool,
}

impl PasskeyFlags {
    pub fn parse(flags: u8) -> Self {
        Self {
            user_present: (flags & 0x01) != 0,
            user_verified: (flags & 0x04) != 0,
            backup_eligible: (flags & 0x08) != 0,
            backup_completed: (flags & 0x10) != 0,
            attested_data: (flags & 0x40) != 0,
            extension_data: (flags & 0x80) != 0,
        }
    }

    pub fn enforce_verification(&self) -> anyhow::Result<()> {
        if !self.user_present || !self.user_verified {
            return Err(anyhow::anyhow!(
                "User presence and authorization cannot be verified"
            ));
        }

        Ok(())
    }
}
