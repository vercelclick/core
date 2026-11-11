use crate::enums::SecretDataType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct SecretDefinition {
    pub name: String,
    pub env_name: String,
    pub project_id: Uuid,
    pub comments: String,
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct SecretValue {
    pub target: Uuid,
    pub name: String,
    pub env_name: String,
    pub project_id: Uuid,
    pub tag: String,
    pub data_type: SecretDataType,
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
}
