use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct SpassEnvironment {
    pub name: String,
    pub project_id: Uuid,
    pub description: String,
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>, // Fixed - invalidates keys if changed
}
