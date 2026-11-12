use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub key_salt: String,
    pub updated_at: DateTime<Utc>,
}
