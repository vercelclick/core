use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, Environment, MachinePublicKey, SecretDefinition,
    SimplifiedEncryptedValue,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub contributor_values: HashMap<String, HashMap<String, SimplifiedEncryptedValue>>,
}

impl SecretWithEncryptedValues {
    pub fn extract(
        definition: &SecretDefinition,
        public_keys: &[ContributorPublicKey],
        mixed_passkey_values: &[ContributorSecretValue],
    ) -> Self {
        let mut contributor_values: HashMap<String, HashMap<String, SimplifiedEncryptedValue>> =
            Default::default();

        for value in mixed_passkey_values {
            if value.name != definition.name {
                continue;
            }

            // TODO! Let's make this a more efficient map
            let cred_id = match public_keys.iter().find(|key| key.id == value.target) {
                Some(pk) => pk.cred_id.clone(),
                None => continue,
            };

            let cred_values = contributor_values.entry(cred_id).or_default();
            cred_values.insert(value.tag.clone(), value.simplify());
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
    pub contributors_keys: Vec<ContributorPublicKey>,
    pub machines_keys: Vec<MachinePublicKey>,
}
