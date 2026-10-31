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
pub struct SimplifiedEncryptedValue {
    pub tag: String,
    pub cred_id: String,
    pub data_type: SecretDataType,
    pub value: String,
    pub created_at: DateTime<Utc>,
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
            value: self.encrypted_value.clone(),
            created_at: self.created_at,
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
