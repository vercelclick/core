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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SimplifiedEncryptedValue {
    pub tag: String,
    pub cred_id: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct ContributorSecretValue {
    pub name: String,
    pub env_name: String,
    pub target: Uuid,
    pub project_id: Uuid,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
}

impl ContributorSecretValue {
    pub fn simplify(&self, cred_id: String) -> SimplifiedEncryptedValue {
        SimplifiedEncryptedValue {
            tag: self.tag.clone(),
            cred_id,
            data_type: self.data_type,
            encrypted_value: self.encrypted_value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct MachineSecretValue {
    pub name: String,
    pub env_name: String,
    pub target: String,
    pub project_id: Uuid,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct ContributorUpdateValue {
    pub target: Uuid,
    pub name: String,
    pub environment: String,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct MachineUpdateValue {
    pub target: String,
    pub environment: String,
    pub name: String,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
}
