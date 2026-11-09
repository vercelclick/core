use crate::enums::SecretDataType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct SecretDefinition {
    pub name: String,
    pub env_name: String,
    pub project_id: Uuid,
    pub comments: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct ContributorSecretValue {
    pub target: Uuid,
    pub name: String,
    pub env_name: String,
    pub project_id: Uuid,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct MachineSecretValue {
    pub target: Uuid,
    pub name: String,
    pub env_name: String,
    pub project_id: Uuid,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretValue {
    pub target: Uuid,
    pub name: String,
    pub environment: String,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
}

impl SecretValue {
    pub fn separate_targets(
        encrypted_values: &[SecretValue],
    ) -> (Vec<SecretValue>, Vec<SecretValue>) {
        let contributor_values: Vec<SecretValue> = encrypted_values
            .iter()
            .filter(|val| val.target.get_version_num() == 7)
            .cloned()
            .collect();

        let machine_values: Vec<SecretValue> = encrypted_values
            .iter()
            .filter(|val| val.target.get_version_num() == 5)
            .cloned()
            .collect();

        (contributor_values, machine_values)
    }
}
