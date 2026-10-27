use secretpass_core::{
    MachinePublicKey, PasskeySecretValue, ProjectUserPasskey, SecretDefinition, SpassEnvironment,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct GetEnvironmentRequest {
    pub env_name: String,
    pub project_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecretWithEncryptedValues {
    pub definition: SecretDefinition,
    pub passkey_values: Vec<PasskeySecretValue>,
}

impl SecretWithEncryptedValues {
    pub fn extract(
        definition: &SecretDefinition,
        mixed_passkey_values: &[PasskeySecretValue],
    ) -> Self {
        let passkey_values: Vec<PasskeySecretValue> = mixed_passkey_values
            .iter()
            .filter(|value| value.name == definition.name)
            .cloned()
            .collect();

        Self {
            definition: definition.clone(),
            passkey_values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GetEnvironmentResult {
    pub environment: SpassEnvironment,
    pub secrets: Vec<SecretWithEncryptedValues>,
    pub passkeys: Vec<ProjectUserPasskey>,
    pub machines: Vec<MachinePublicKey>,
}
