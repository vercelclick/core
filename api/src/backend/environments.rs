use secretpass_core::{ContributorPublicKey, Environment, SecretDefinition, SecretValue};
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
    pub contributor_values: Vec<(ContributorPublicKey, SecretValue)>,
}

impl SecretWithEncryptedValues {
    pub fn extract(
        definition: &SecretDefinition,
        public_keys: &[ContributorPublicKey],
        secret_values: &[SecretValue],
    ) -> Self {
        let mut contributor_values: Vec<(ContributorPublicKey, SecretValue)> = Default::default();

        for value in secret_values {
            if value.name != definition.name {
                continue;
            }

            // TODO! Let's make this a more efficient map
            let public_key = match public_keys.iter().find(|key| key.id == value.target) {
                Some(pk) => pk.clone(),
                None => continue,
            };

            contributor_values.push((public_key, value.clone()));
        }

        Self {
            definition: definition.clone(),
            contributor_values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GetEnvironmentResult {
    pub environment: Environment,
    pub secrets: Vec<SecretWithEncryptedValues>,
}
