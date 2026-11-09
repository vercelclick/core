use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct Passkey {
    pub user_id: Uuid,
    pub name: String,
    pub cred_id: String, // Base64url-encoded credential id
    pub key_salt: String,
    pub public_key: String,
    pub web_public_key: String, // Base64url-encoded COSE key
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
